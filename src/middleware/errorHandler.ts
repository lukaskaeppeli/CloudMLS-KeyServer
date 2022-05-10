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

import { ErrorRequestHandler } from "express";
import { accessCookieOptions, refreshCookieOptions } from "../controllers/cookieConfig";

export class BadRequestError extends Error {
    code = 400
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, BadRequestError.prototype);
    }
}

export class MongoDbError extends Error {
    code = 500
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, MongoDbError.prototype);
    }
}

export class NotFoundError extends Error {
    code = 404
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, NotFoundError.prototype);
    }
}

export class AccountError extends Error {
    code = 400
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, AccountError.prototype);
    }
}

export class ConflictError extends Error {
    code = 409
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, ConflictError.prototype);
    }
}

export class CustomKeyServerError extends Error {
    code = 409
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, CustomKeyServerError.prototype);
    }
}


export class UserError extends Error {
    code = 400
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, UserError.prototype);
    }
}


export class TokenRefreshError extends Error {
    code = 403 // Don't change!
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, TokenRefreshError.prototype);
    }
}


export class TokenVerificationError extends Error {
    code = 401 // Don't change!
    constructor(message: string) {
        super(message)
        Object.setPrototypeOf(this, TokenVerificationError.prototype);
    }
}



export const errorHandler: ErrorRequestHandler = (error, req, res, next) => {
    console.log(`Handling ${error.constructor.name}: ${error.message}`)

    switch (error.constructor) {
        case MongoDbError:
            res.status(error.code).send({ message: error.message })
            next(error)
            break

        case TokenRefreshError:
            res.cookie("accessToken", '', { ...accessCookieOptions, maxAge: 0 })
            res.cookie("refreshToken", '', { ...refreshCookieOptions, maxAge: 0 })
            res.status(error.code).send({ message: error.message })
            break

        case BadRequestError:
        case NotFoundError:
        case AccountError:
        case ConflictError:
        case CustomKeyServerError:
        case UserError:
        case TokenVerificationError:
            res.status(error.code).send({ message: error.message })
            break
        default:
            next(error)
    }

}
