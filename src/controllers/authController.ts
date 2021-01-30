import { ObjectId } from "mongoose"
import { Request, Response } from "express"
import bcrypt from "bcrypt"

import * as token from "./token"
import * as emailValidator from "./emailValidator"
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
    const newUser = await User.create({ email: body.email, username: body.username, passwordHash: passwordHash });
    // Send token to email
    await emailValidator.sendTokenToEmail(newUser._id, body.email);
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

    const accessToken = token.generateAccessToken(user._id);
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
    let userId;
    try {
        userId = token.verifyAccessToken(body.accessToken);
    } catch (err) {
        return res.status(400).send("Unauthorized refresh");
    }
    const user = await User.findById(userId).exec();
    if (user.refreshToken != body.refreshToken) {
        //TODO: Initiate the destruction protocol, refresh token is somehow invalid
        user.refreshToken = undefined;
        await user.save();
        return res.status(400).send("Unauthorized refresh");
    }

    const newAccessToken = token.generateAccessToken(user._id);
    const newRefreshToken = token.generateRefreshToken();
    user.refreshToken = newRefreshToken;
    await user.save();

    const responseJson: RefreshResponseBody = { newAccessToken, newRefreshToken };
    res.status(200).json(responseJson);
}

interface PostValidateEmailRequestBody {
    // TODO: userId actually is encoded in access token
    userId: ObjectId
    token: string
}

export const postValidateEmail = async (req: Request, res: Response) => {
    const body: PostValidateEmailRequestBody = req.body;
    // TODO: get userId from access token
    if (!await emailValidator.validateEmail(body.userId, body.token)) {
        return res.status(400).send("Wrong token");
    }

    res.sendStatus(200);
}