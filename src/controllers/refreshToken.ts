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

import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from 'jsonwebtoken';
import { TokenRefreshError } from "../middleware/errorHandler";
import { User } from '../models/user';
import { accessCookieOptions, refreshCookieOptions, TokenExpiration } from "./cookieConfig";


/**
 * If refreshing the token fails in any kind, we return a status 403
 */
export function refreshToken(req: Request, res: Response, next: NextFunction) {
    if (req.cookies && req.cookies.refreshToken) {
        jwt.verify(req.cookies.refreshToken, process.env.REFRESH_TOKEN_SECRET!, (err: any, decoded: any) => {
            if (err) next(new TokenRefreshError(err.message))
            if (!decoded) next(new TokenRefreshError("decoded jwt is undefined"))

            let jwtPayload = decoded as JwtPayload
            User.findOne({
                _id: jwtPayload["id"]
            }).exec((err, user) => {
                if (err) {
                    next(new TokenRefreshError(err.message))
                } else if (!user) {
                    next(new TokenRefreshError("User not found"))
                } else {
                    // Refresh token ok, issue new access token
                    var accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: TokenExpiration.Access });
                    res.cookie('accessToken', accessToken, accessCookieOptions)

                    // Create new refresh token and assign it to user
                    let newRefreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET!, { expiresIn: TokenExpiration.Refresh })
                    res.cookie('refreshToken', newRefreshToken, refreshCookieOptions)

                    res.status(204).send()
                }
            })
        });
    } else {
        next(new TokenRefreshError("No or invalid refresh token provided"))

    }
}