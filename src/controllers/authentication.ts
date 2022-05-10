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

import { compareSync, genSaltSync, hashSync } from 'bcrypt';
import { NextFunction, Request, Response } from "express";
import * as jwt from 'jsonwebtoken';
import { MongoDbError, UserError } from '../middleware/errorHandler';
import { User } from '../models/user';
import { accessCookieOptions, refreshCookieOptions, TokenExpiration } from './cookieConfig';

export function register(req: Request, res: Response, next: NextFunction) {

    // Upon calling bcrypt.hashSync(String, number), bcrypt will 
    // autogenerate a salt, using bcrypt.genSaltSync(number)
    
    User.findOne({ username: req.body.username }).exec((err, existing_user) => {
        if (!err && existing_user) {
            next(new UserError("Username already taken"))
        } else {
            const user = new User({
                username: req.body.username,
                password_hash: hashSync(req.body.password, 8),
                customKeyServer: req.body.customKeyServer,
                keyserver_key_salt: genSaltSync(),
                local_key_salt: genSaltSync(),
                local_user_salt: genSaltSync()
            });

            user.save((err, user) => {
                if (err) {
                    next(new MongoDbError("Failed to register " + err.message))
                } else {
                    res.status(200)
                        .send({
                            message: "User registered successfully"
                        })
                }
            });
        }
    })


};

export function login(req: Request, res: Response, next: NextFunction) {
    User.findOne({
        username: req.body.username
    }).populate('accounts').exec((err, user) => {
        if (err) {
            next(new MongoDbError(err.message))
        } else if (!user) {
            next(new UserError("Invalid username / password"))
        } else {

            //comparing passwords
            var passwordIsValid = compareSync(req.body.password, user.password_hash);

            // checking if password was valid and send response accordingly
            if (!passwordIsValid) {
                next(new UserError("Invalid username / password"))
            } else {

                // sign token with user id
                var accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: TokenExpiration.Access });
                res.cookie('accessToken', accessToken, accessCookieOptions)

                // generate refresh token
                var refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET!, { expiresIn: TokenExpiration.Refresh })

                res.cookie('refreshToken', refreshToken, refreshCookieOptions)

                let accountResponse = []
                for (let account of user.accounts) {
                    accountResponse.push({
                        "account_id": account.account_id.split('/')[1],
                        "platform": account.account_id.split('/')[0],
                        "keypackage": account.keypackage
                    })
                }

                // responding to client request with user profile success message and access token .
                res.status(200)
                    .send({
                        username: user.username,
                        accounts: accountResponse,
                        accessToken: accessToken,
                        keyserver_key_salt: user.keyserver_key_salt,
                        local_key_salt: user.local_key_salt,
                        local_user_salt: user.local_user_salt
                    });
            }
        }
    });
};

export function logout(req: Request, res: Response) {
    res.cookie("accessToken", '', { ...accessCookieOptions, maxAge: 0 })
    res.cookie("refreshToken", '', { ...refreshCookieOptions, maxAge: 0 })
    res.sendStatus(204)
}
