import { Request, Response } from "express"
import bcrypt from "bcrypt"

import * as token from "./token"
import User from "../models/user"

interface SignupRequestBody {
    email: string
    username: string
    password: string
}

export const postSignup = async (req: Request<{}, {}, SignupRequestBody>, res: Response) => {
    const body: SignupRequestBody = req.body;
    // Check if the email is unique
    let user = await User.findOne({ email: body.email }).exec();
    if (user) {
        return res.status(400).send("A user with the given email already exists");
    }
    // Check if the username is unique 
    user = await User.findOne({username: body.username }).exec();
    if (user) {
        return res.status(400).send("A user with the given username already exists");
    }
    // Create new user
    const passwordHash = await bcrypt.hash(body.password, 10);
    await User.create({ email: body.email, username: body.username, passwordHash: passwordHash });
    res.sendStatus(200);
}

interface LoginRequestBody {
    username: string
    password: string
}

interface LoginResponseBody {
    accessToken: string,
    refreshToken: string
}

export const postLogin = async (req: Request, res: Response) => {
    const body: LoginRequestBody = req.body;
    const user = await User.findOne({ username: body.username }).exec();
    if (!user) {
        return res.status(400).send("A user with the given username doesn't exist");
    }
    if (!await bcrypt.compare(body.password, user.passwordHash)) {
        return res.status(400).send("Wrong password");
    }

    const accessToken = token.generateAccessToken(body.username);
    const refreshToken = token.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save();

    const responseJson: LoginResponseBody = { accessToken, refreshToken };
    res.status(200).json(responseJson);
}

interface RefreshRequestBody {
    accessToken: string,
    refreshToken: string
}

interface RefreshResponseBody {
    newAccessToken: string,
    newRefreshToken: string
}

export const postRefresh = async (req: Request, res: Response) => {
    const body: RefreshRequestBody = req.body;
    const tokenUsername = token.verifyAccessToken(body.accessToken);
    const user = await User.findOne({ username: tokenUsername }).exec();
    if (user.refreshToken != body.refreshToken) {
        //TODO: Initiate the destruction protocol, refresh token is somehow invalid
    }

    const newAccessToken = token.generateAccessToken(user.username);
    const newRefreshToken = token.generateRefreshToken();
    user.refreshToken = newRefreshToken;
    await user.save();

    const responseJson: RefreshResponseBody = { newAccessToken, newRefreshToken };
    res.status(200).json(responseJson);
}

