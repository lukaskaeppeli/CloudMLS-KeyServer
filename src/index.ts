/*
Copyright 2022 Lukas Käppeli

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import cors from 'cors';
import express from "express";
import mongoose from 'mongoose';
import { login, logout, register } from './controllers/authentication';
import { refreshToken } from './controllers/refreshToken';
import { AccountError, BadRequestError, ConflictError, CustomKeyServerError, errorHandler, MongoDbError, NotFoundError, UserError } from './middleware/errorHandler';
import { verifyToken } from './middleware/tokenVerification';
import { Account, GroupState, User } from './models/user';
import { authRouter } from './routes/user';
import { resolveAccount, resolveGroup } from './utils/utils';
import cookieParser from 'cookie-parser';
import { createServer } from 'https';
import { readFileSync } from 'fs';


// Load environment
require('dotenv').config();

// Connect to database
const mongodbOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    family: 4
}

mongoose.connect(`${process.env.MONGODB_URL}/${process.env.MONGODB_DATABASE}`, mongodbOptions, err => {
    if (err) {
        console.error('Error! ' + err)
    } else {
        console.log('Connected to mongodb')
    }
});


const app = express();

app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true
}))

// parse requests of content-type - application/json
app.use(express.json());

// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

// Cookies
app.use(cookieParser())

// logging
// app.use(function (req, res, next) { console.log(req.method + ' ' + req.originalUrl); next(); console.log(res.statusCode) });

// register and login functionality
app.use(authRouter);

// set up router
const router = express.Router()
router.post("/auth/register", register, function (req, res, next) { });
router.post("/auth/login", login, function (req, res, next) { });
router.post("/auth/logout", verifyToken, logout, function (req, res) { });
router.post("/auth/refresh", refreshToken, function (req, res, next) { });

/**
 * Used to check if the server is reachable
 */
app.get('/', (_, res) => {
    res.send(
        {
            "status": 200
        })
})


/**
 * GENERAL: User is identified by token id
 */

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                      //
//                                         AUTHENTICATION SERVER                                        //
//                                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////////////////////

// This server servers for two purposes:
//  - First, for storing a keypackage for each Account associated with Athena. We therefore use
//    the datastructure Authentication_Keypackage
//  - Second, for storing each registered user, as well as all his associated accounts. We may
//    use this later on also to enable transfers of those associated accounts across devices. 

/**
 * Adds a new platform account to the user
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in body, set by client
 * @param account_id Account_id on the specified platform, in body, set by client
 * @returns 204, if user added successfully
 */
app.post('/account', verifyToken, (req, res, next) => {
    // Check if we have all data needed
    let userId = req.body.userId
    let platform = req.body.platform
    let account_id = req.body.account_id

    if (!userId || !platform || !account_id) {
        next(new BadRequestError("Missing platform or account_id"))
        return
    }

    let combined_id = platform + "/" + account_id

    // Find user
    User.findById(userId).populate('accounts').exec(async (err, user) => {
        if (err) {
            next(new MongoDbError(err.message))
            return
        } else if (!user) {
            next(new UserError("User not found"))
            return
        } else {

            // Check if account is already registered
            for (let account of user.accounts) {
                if (account.account_id == combined_id) {
                    next(new AccountError("Account already registerd"))
                    return
                }
            }

            // If not, we create a new one
            let account = new Account({
                account_id: combined_id,
                keypackage: "",
                inbox: [],
                keypackageData: "",
                groupStates: []
            })

            // Create new Account and assign to user
            account.save((err: any, account: any) => {
                if (err) {
                    next(new MongoDbError(err.message))
                    return
                }

                if (!account) {
                    next(new MongoDbError("Failed to save new Account"))
                    return
                }

                user.accounts.push(account)
                user.save((err: any, user: any) => {
                    if (err) {
                        next(new MongoDbError(err.message))
                    } else {
                        res.sendStatus(204)
                    }
                })
            })
        }
    })
})

/**
 * - Replaces the keypackage stored in the public accessible field, if
 *   the user provides the currently stored keypackage. This prevents
 *   that the keypackage is changed by two instances of the same client
 *   at the same time. 
 * - Sets the keypackage data of specified account, if the user doesn't
 *   run a custom keyserver and the keypackage update was successful.
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in body, set by client
 * @param account_id Account_id on the specified platform, in body, set by client
 * @param keypackage new keypackage, in body, set by client
 * @param keypackageData private keys of keypackage, in body, set by client if
 *                       no custom keyserver is active
 * @param oldKeypackage old keypackage for comparison that no intermediate update
 *                      happend, in body, set by client
 * @returns 204, if update was successful
 */
app.post('/keypackage', verifyToken, async (req, res, next) => {
    // Check if we have all data needed
    let userId = req.body.userId
    let platform = req.body.platform
    let account_id = req.body.account_id
    let keypackage = req.body.keypackage
    let keypackageData = req.body.keypackageData
    let oldKeypackage = req.body.oldKeypackage // Only parameter that can be undefined

    if (!userId || !platform || !account_id || !keypackage) {
        next(new BadRequestError("Missing platform, account_id or keypackage"))
        return
    }

    let combined_id = platform + "/" + account_id

    // Find specified account of user
    resolveAccount(userId, combined_id).then(
        ([accountObject_id, customKeyServer]) => {

            // Update account
            Account.findById(accountObject_id).exec((err, account) => {
                if (err) {
                    next(new MongoDbError(err.message))
                    return
                }
                if (!account) {
                    next(new NotFoundError("Account not found"))
                    return
                }

                if (account.keypackage == "" || account.keypackage == oldKeypackage) {
                    account.keypackage = keypackage

                    if (!customKeyServer) {
                        account.keypackageData = keypackageData
                    }
                } else {
                    next(new ConflictError("Keypackage updated in the meantime"))
                    return
                }

                account.save((err, account) => {
                    if (err) {
                        next(new MongoDbError(err.message))
                    } else {
                        res.sendStatus(204)
                    }
                })

            })
        },
        (error) => {
            next(error)
        })

})

/**
 * Returns the keypackage of a specified account. Note that the userId is
 * not checked here as a user can request keypackages of every other user
 * 
 * @param platform Platform to be registered, in params, set by client
 * @param account_id Account_id on the specified platform, in params, set by client
 * @returns { response: keypackage } if the keypackage is found
 */
app.get('/keypackage/:platform/:account_id', verifyToken, (req, res, next) => {
    let platform = req.params.platform
    let account_id = req.params.account_id

    if (!platform || !account_id) {
        next(new BadRequestError("Missing platform or account_id"))
        return
    }

    let combined_id = platform + "/" + account_id

    Account.findOne({ account_id: combined_id }).exec((err, account) => {
        if (err) {
            next(new MongoDbError(err.message))
            return
        }

        if (!account) {
            next(new NotFoundError("Account not found"))
        } else {
            res.status(200).send({ response: account.keypackage })
        }
    })
})


//////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                      //
//                                             KEY SERVER                                               //
//                                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Returns the keypackage of a specified account. In contrast to the keypackage
 * we need to check that the user only requests its own keypackages
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in params, set by client
 * @param account_id Account_id on the specified platform, in params, set by client
 * @returns { response: keypackage } if the keypackage is found
 */
app.get('/keypackagedata/:platform/:account_id', verifyToken, async (req, res, next) => {
    let userId = req.body.userId
    let platform = req.params.platform
    let account_id = req.params.account_id

    if (!userId || !platform || !account_id) {
        next(new BadRequestError("Missing platform or account_id"))
        return
    }

    let combined_id = platform + "/" + account_id

    resolveAccount(userId, combined_id).then(
        ([accountObject_id, customKeyServer]) => {
            if (customKeyServer) {
                res.status(400).send({ message: "If you run your own keyserver, you must request this data from there." })
                return
            }

            Account.findById(accountObject_id).exec((err, account) => {
                if (err) {
                    next(new MongoDbError(err.message))
                } else if (!account) {
                    next(new NotFoundError("Account not found"))
                } else {
                    res.status(200).send({ response: account.keypackageData })
                }
            })
        },
        (error) => {
            next(error)
        })
})


/**
 * Requests all group states of one account if the user does not run
 * a custom keyserver
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in params, set by client
 * @param account_id Account_id on the specified platform, in params, set by client
 * @returns the requested group state as an array
 */
app.get("/groups/:platform/:account_id", verifyToken, (req, res, next) => {
    let userId = req.body.userId
    let platform = req.params.platform
    let account_id = req.params.account_id

    if (!userId || !platform || !account_id) {
        next(new BadRequestError("Missing platform or account_id"))
        return
    }

    let combined_id = platform + "/" + account_id

    resolveAccount(userId, combined_id).then(
        ([accountObject_id, customKeyServer]) => {
            if (customKeyServer) {
                next(new CustomKeyServerError("If you run your own keyserver, you must request this data from there."))
                return
            }

            Account.findById(accountObject_id).populate('groupStates').exec((err, account) => {
                if (err) {
                    next(new MongoDbError(err.message))
                } else if (!account) {
                    next(new NotFoundError("Account not found"))
                } else {

                    let groups = []
                    for (let group of account.groupStates) {
                        groups.push(group.group_id.split('/')[1])
                    }

                    res.status(200).send({
                        response: {
                            groups: groups
                        }
                    })

                    return
                }
            })
        },
        (error) => {
            next(error)
        }
    )
})

/**
 * Requests the specified group state if the user does not run
 * a custom keyserver
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in params, set by client
 * @param account_id Account_id on the specified platform, in params, set by client
 * @param group_id The id of the requested group, in params, set by client
 * @returns the requested group state as JSON in the format:
 *        {
 *          group_id: string,
 *          members: string,
 *          creationTime: string,
 *          mlsGroup: string,
 *          latestEpoch: string
 *        }
 */
app.get("/groups/:platform/:account_id/:group_id", verifyToken, (req, res, next) => {
    let userId = req.body.userId
    let platform = req.params.platform
    let account_id = req.params.account_id
    let group_id = req.params.group_id

    if (!userId || !platform || !account_id || !group_id) {
        next(new BadRequestError("Missing platform, account_id or group_id"))
        return
    }

    let combined_id = platform + "/" + account_id
    group_id = account_id + "/" + group_id

    resolveAccount(userId, combined_id).then(
        ([accountObject_id, customKeyServer]) => {
            if (customKeyServer) {
                next(new CustomKeyServerError("If you run your own keyserver, you must request this data from there."))
                return
            }

            Account.findById(accountObject_id).populate('groupStates').exec((err, account) => {
                if (err) {
                    next(new MongoDbError(err.message))
                } else if (!account) {
                    next(new NotFoundError("Account not found"))
                } else {

                    for (let group of account.groupStates) {
                        if (group.group_id == group_id) {
                            res.status(200).send({
                                response: {
                                    group_id: group.group_id.split("/")[1],
                                    members: group.members,
                                    creationTime: group.creationTime,
                                    mlsGroup: group.mlsGroup,
                                    updateCounter: group.updateCounter,
                                    latestEpoch: group.latestEpoch
                                }
                            })
                            return
                        }
                    }

                    next(new NotFoundError("No group with specified id on keyserver."))
                }
            })
        },
        (error) => {
            next(error)
        }
    )
})

/**
 * Updates the specified group state
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in body, set by client
 * @param account_id Account_id on the specified platform, in body, set by client
 * @param group_id The id of the requested group, in body, set by client
 * @param members The members of the group as string array, in body, set by client
 * @param creationTime The creation time of the group, in body, set by client
 * @param mlsGroup Serialized MLS datastructure, in body, set by client
 * @param latestEpoch latest epoch, e.g. maximum epoch, in body, set by client
 * @returns 204 if group updated successfully
 */
app.post("/groups", verifyToken, (req, res, next) => {
    let userId = req.body.userId
    let platform = req.body.platform
    let account_id = req.body.account_id
    let group_id = req.body.group_id
    let members = req.body.members
    let creationTime = req.body.creationTime
    let mlsGroup = req.body.mlsGroup
    let latestEpoch = req.body.latestEpoch
    let updateCounter = req.body.updateCounter

    if (!userId || !platform || !account_id || !group_id || !members || !creationTime || !mlsGroup || !latestEpoch || !updateCounter) {
        next(new BadRequestError("Missing platform, account_id, group_id, members, creationTime, mlsGroup, latestEpoch or updateCounter"))
        return
    }

    let combined_id = platform + "/" + account_id
    group_id = account_id + "/" + group_id


    resolveAccount(userId, combined_id).then(
        ([accountObject_id, customKeyServer]) => {
            if (customKeyServer) {
                next(new CustomKeyServerError("If you run your own keyserver, you must post this data there."))
                return
            }

            Account.findById(accountObject_id).exec((err, account) => {
                if (err) {
                    next(new MongoDbError(err.message))
                } else if (!account) {
                    next(new NotFoundError("Account not found"))
                } else {

                    resolveGroup(accountObject_id, group_id).then(
                        (groupObject_id) => {
                            if (!groupObject_id) {

                                // Group does not exist yet, thus we create it
                                let newGroupState = new GroupState({
                                    group_id: group_id,
                                    members: members,
                                    creationTime: creationTime,
                                    mlsGroup: mlsGroup,
                                    updateCounter: updateCounter,
                                    latestEpoch: latestEpoch
                                })

                                newGroupState.save((err, group) => {
                                    if (err) {
                                        next(new MongoDbError(err.message))
                                    } else if (!group) {
                                        next(new MongoDbError("Failed to save new group"))
                                    } else {
                                        account.groupStates.push(group)
                                        account.save((err, _) => {
                                            if (err) {
                                                next(new MongoDbError(err.message))
                                            } else {
                                                res.sendStatus(204)
                                            }
                                        })
                                    }
                                })
                            } else {
                                // Group exists, thus we update it
                                GroupState.findById(groupObject_id).exec((err, group) => {
                                    if (err) {
                                        next(new MongoDbError(err.message))
                                    } else if (!group) {
                                        next(new MongoDbError("Failed to load existing group"))
                                    } else {

                                        // Ensure that group state was not modified in the meantime
                                        // If the updateCounter is 1, a member was removed and added again
                                        if (updateCounter > 1 && updateCounter != group.updateCounter + 1) {
                                            next(new ConflictError("GroupState modified in the meantime"))
                                        } else {
                                            group.members = members
                                            group.creationTime = creationTime
                                            group.mlsGroup = mlsGroup
                                            group.updateCounter = updateCounter
                                            group.latestEpoch = latestEpoch

                                            group.save((err, _) => {
                                                if (err) {
                                                    next(new MongoDbError(err.message))
                                                } else {
                                                    res.sendStatus(204)
                                                }
                                            })
                                        }
                                    }
                                })
                            }
                        },
                        (error) => {
                            next(error)
                        })
                }
            })


        },
        (error) => {
            next(error)
        })
})


//////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                      //
//                                          DELIVERY SERVER                                             //
//                                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Gets the inbox for the specified account. The inbox will be empty afterwards
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform to be registered, in params, set by client
 * @param account_id Account_id on the specified platform, in params, set by client
 * @returns The content of the inbox as string array
 **/

app.get("/delivery/:platform/:account_id", verifyToken, (req, res, next) => {
    let userId = req.body.userId
    let platform = req.params.platform
    let account_id = req.params.account_id

    if (!userId || !platform || !account_id) {
        next(new BadRequestError("Missing platform or account_id"))
        return
    }

    let combined_id = platform + "/" + account_id

    resolveAccount(userId, combined_id).then(
        ([accountObject_id, _]) => {
            Account.findById(accountObject_id).exec((err, account) => {
                if (err) {
                    next(new MongoDbError(err.message))
                } else if (!account) {
                    next(new NotFoundError("Account not found"))
                } else {

                    // Clone inbox such that we can empty the inbox and return errors
                    // when that does not succeed
                    let cloned_inbox = account.inbox.slice()

                    account.inbox = []
                    account.save((err, _) => {
                        if (err) {
                            next(new MongoDbError(err.message))
                        } else {
                            res.status(200).send({ response: cloned_inbox })
                        }
                    })
                }
            })
        },
        (error) => {
            next(error)
        }
    )
})


/**
 * Goes throught an array of new messages and pushes each new message to the 
 * corresponding account. Only return if all messages were stored correctly.
 * Note that each member can send messages to any other member. We therefore 
 * do not need to use the function resolveAccount()
 * 
 * @param userId Gets set when verifyToken succeeds
 * @param platform Platform of the receiver, in body, set by client
 * @param account_id Account_id of the receiver on the specified platform, in body, set by client
 * @param message The message to be stored in the specified inbox, in body, set by client
 * @returns 204 if the message was stored successfully
 **/
app.post("/delivery", verifyToken, async (req, res, next) => {
    let userId = req.body.userId

    const promises = []
    for (let message of req.body) {
        promises.push(
            new Promise<void>((resolve, reject) => {
                let platform = message.platform
                let account_id = message.receiver
                let content = message.message

                if (!userId || !platform || !account_id || !content) {
                    return reject(new BadRequestError("Missing platform, account_id or message in at least one message"))
                }

                let combined_id = platform + "/" + account_id

                Account.findOne({ account_id: combined_id }).exec((err, account) => {
                    if (err) return reject(new MongoDbError(err.message))

                    if (!account) {
                        return reject(new NotFoundError("Account not found"))
                    } else {

                        account.inbox.push(content)
                        account.save((err, _) => {
                            if (err) return reject(new MongoDbError(err.message))
                            return resolve()
                        })
                    }
                })
            })
        )
    }

    Promise.all(promises).then(
        () => {
            // All messages pushed successfully
            res.sendStatus(204)
        },
        error => {
            next(error)
        }
    )
})


// error handler
app.use(errorHandler)

// start the express server
if (process.env.NODE_ENV === 'production') {
    createServer({
        key: readFileSync(process.env.SSL_PRIV_KEY!),
        cert: readFileSync(process.env.SSL_CERT!)
    }, app).listen(process.env.PORT, () => {
        console.log(`Production server started at https://localhost:${process.env.PORT}`);
    });
} else {
    app.listen(process.env.PORT, () => {
        // tslint:disable-next-line:no-console
        console.log(`Developement server started at http://localhost:${process.env.PORT}`);
    });
}

