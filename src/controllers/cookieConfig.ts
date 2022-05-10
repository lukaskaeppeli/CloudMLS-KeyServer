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

import { CookieOptions } from 'express'

require('dotenv').config();

export enum TokenExpiration {
    Access = 10 * 60, // 10 minutes
    Refresh = 7 * 24 * 60 * 60, // 7 days
}

export const refreshCookieOptions: CookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.BASE_DOMAIN,
    path: '/',
    maxAge: TokenExpiration.Refresh * 1000,
}


export const accessCookieOptions: CookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.BASE_DOMAIN,
    path: '/',
    maxAge: TokenExpiration.Access * 1000,
}
