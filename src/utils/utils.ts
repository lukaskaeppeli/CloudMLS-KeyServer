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

import { MongoDbError, NotFoundError, UserError } from "../middleware/errorHandler"
import { Account, GroupState, User } from "../models/user"


export function resolveAccount(userId: string, accountId: string): Promise<[string, boolean]> {
    return new Promise((resolve, reject) => {
        User.findById(userId).populate('accounts').exec((err, user) => {
            if (err) return reject(new MongoDbError(err.message))
            if (!user) return reject(new UserError("User not found"))

            if (!user.accounts.map(account => account.account_id).includes(accountId)) {
                return reject(new NotFoundError("Account not found"))
            }

            for (let acc_id of user.accounts) {
                Account.findById(acc_id).exec((err, account) => {
                    if (err) return reject(new MongoDbError(err.message))
                    if (!account) return reject(new NotFoundError("Account not found"))

                    if (account.account_id === accountId) {
                        return resolve([account._id.toString(), user.customKeyServer])
                    }
                })
            }
        })
    })
}


export function resolveGroup(accountObject_Id: string, groupId: string): Promise<any> {
    return new Promise((resolve, reject) => {
        Account.findById(accountObject_Id).populate('groupStates').exec((err, account) => {
            if (err) return reject(new MongoDbError(err.message))
            if (!account) return reject(new NotFoundError("Account not found"))

            if (!account.groupStates.map(GroupState => GroupState.group_id).includes(groupId)) {
                return resolve(undefined)
            }

            for (let group_id of account.groupStates) {
                GroupState.findById(group_id).exec((err, group) => {
                    if (err) return reject(new MongoDbError(err.message))
                    if (!group) return resolve(undefined)

                    if (group.group_id === groupId) {
                        return resolve(group._id.toString())
                    }
                })
            }
        })
    })
}