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

import { NextFunction, Request, Response } from 'express';
import jwt, { JwtPayload, TokenExpiredError } from 'jsonwebtoken';
import { User } from '../models/user';
import { TokenVerificationError } from './errorHandler';


export function verifyToken(req: Request, res: Response, next: NextFunction) {
    if (req.cookies && req.cookies.refreshToken) {
        jwt.verify(req.cookies.refreshToken, process.env.ACCESS_TOKEN_SECRET!, (err: any, decoded: any) => {

            if (err && err instanceof TokenExpiredError) {
                next(new TokenVerificationError("Token expired"))
            } else if (err) {
                next(new TokenVerificationError(err.message))
            } else if (!decoded) {
                next(new TokenVerificationError("Decoded is undefined"))
            } else {
                let jwtPayload = decoded as JwtPayload
                User.findOne({
                    _id: jwtPayload["id"]
                }).exec((err, user) => {
                    if (err) {
                        next(new TokenVerificationError(err.message))
                    } else {
                        req.body.userId = user?._id;
                        next();
                    }
                })
            }
        });
    } else {
        next(new TokenVerificationError("No or malformed token provided"))
    }
};
