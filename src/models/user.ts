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

import { model, Schema } from "mongoose";

/**
 * Intefaces
 */
interface User {
    username: string,
    password_hash: string,
    customKeyServer: boolean,
    keyserver_key_salt: string,
    local_key_salt: string,
    local_user_salt: string,
    accounts: Account[]
}

interface GroupState {
    group_id: string,
    updateCounter: number,      // Used to ensure consistency
    members: string,            // Encrypted
    creationTime: string,       // Encrypted
    mlsGroup: string,           // Encrypted
    latestEpoch: string         // Encrypted
}

const groupStateSchema = new Schema<GroupState>({
    group_id: {
        type: String,
        unique: true,
        lowercase: true,
        trim: true,
        required: [true, "group_id not provided"],
    },

    updateCounter: {
        type: Number,
        default: 0
    },

    members: {
        type: String
    },

    creationTime: {
        type: String
    },

    mlsGroup: {
        type: String
    },

    latestEpoch: {
        type: String
    }
})

/**
 * Inbox.messages has the form: 
 * 
 * JSON.stringify({
 *    src_account: string, 
 *    group_id: string, 
 *    message_type: number, 
 *    creation_time: number, 
 *    mls_message: string
 * })
 * 
 *
 * keypackageData has the form:
 * 
 * JSON.stringify({
 *      "keypackage": string, 
 *      "signingPrivateKey": string, 
 *      "signingPublicKey": string, 
 *      "hpkePrivateKey": string,
 *      "hpkePublicKey": string,
 *      "credential": string
 * })
 */
interface Account {
    account_id: string,         // Format: platformname/account_id
    keypackage: string,
    inbox: string[],
    keypackageData: string,     // Encrypted
    groupStates: GroupState[]
}

/**
 * Account Schema
 */
const accountSchema = new Schema<Account>({
    account_id: {
        type: String,
        unique: true,
        lowercase: true,
        trim: true,
        required: [true, "account_id not provided"],
    },

    keypackage: {
        type: String,
        default: ""
    },

    inbox: [{
        type: String,
        default: []
    }],

    keypackageData: {
        type: String
    },

    groupStates: [{
        type: Schema.Types.ObjectId, ref: 'GroupState',
        default: []
    }]
})

/**
 * User Schema
 */
const userSchema = new Schema<User, Account>({
    username: {
        type: String,
        unique: true,
        lowercase: true,
        trim: true,
        required: [true, "username not provided"],
        minLength: [8, '{VALUE} username must be at least 8 characters long!'],
        maxLenght: [20, '{VALUE} username can not be longer than 20 characters!']
    },

    password_hash: {
        type: String,
        required: true
    },

    customKeyServer: {
        type: Boolean,
        default: false
    },

    keyserver_key_salt: {
        type: String,
        default: ""
    },

    local_key_salt: {
        type: String,
        default: ""
    },

    local_user_salt: {
        type: String,
        default: ""
    },

    accounts: [{
        type: Schema.Types.ObjectId, ref: 'Account',
    }]
});

export const User = model('User', userSchema);
export const Account = model('Account', accountSchema);
export const GroupState = model('GroupState', groupStateSchema)
