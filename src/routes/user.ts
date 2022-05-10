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

import express from 'express'
import { register, login, logout } from '../controllers/authentication'
import { refreshToken } from '../controllers/refreshToken';
import { verifyToken } from '../middleware/tokenVerification';

export const authRouter = express.Router()

authRouter.post("/auth/register", register, function (req, res, next) {

});

authRouter.post("/auth/login", login, function (req, res, next) {

});

authRouter.post("/auth/logout", verifyToken, logout, function (req, res) {

});

authRouter.post("/auth/refresh", refreshToken, function (req, res, next) {

});
