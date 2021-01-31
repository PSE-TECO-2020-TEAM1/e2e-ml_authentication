import { Request, Response } from "express"
import bcrypt from "bcrypt"
import crypto from "crypto"
import { ObjectId } from "mongoose"

import * as token from "./token"
import User from "../models/user"
import { EmailVerificationToken } from "../models/emailToken"
import constants from "../config/constants.json"
import * as email from "./email"

interface SignupRequestBody {
    email: string
    username: string
    password: string
}

export const postSignup = async (req: Request, res: Response) => {
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
    // Send email validation token
    const verificationToken = crypto.randomBytes(constants.EMAIL_TOKEN_SIZE_IN_BYTES).toString("hex");
    await EmailVerificationToken.create({ userId: newUser._id, token: verificationToken});
    await email.sendVerificationEmail(body.email, verificationToken)

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
    userId: ObjectId,
    refreshToken: string
}

interface RefreshResponseBody {
    newAccessToken: string,
    newRefreshToken: string
}

export const postRefresh = async (req: Request, res: Response) => {
    const body: RefreshRequestBody = req.body;

    const user = await User.findById(body.userId).exec();
    if (user.refreshToken != body.refreshToken) {
        user.refreshToken = undefined;
        await user.save();
        return res.sendStatus(401);
    }

    const newAccessToken = token.generateAccessToken(body.userId);
    const newRefreshToken = token.generateRefreshToken();
    user.refreshToken = newRefreshToken;
    await user.save();

    const responseJson: RefreshResponseBody = { newAccessToken, newRefreshToken };
    res.status(200).json(responseJson);
}

interface PostVerifyEmailRequestQuery extends qs.ParsedQs {
    token: string
}

export const postVerifyEmail = async (req: Request<{}, {}, {}, PostVerifyEmailRequestQuery>, res: Response) => {
    const query = req.query;
    // TODO: get userId from access token
    const verificationToken = await EmailVerificationToken.findOneAndDelete({ token: query.token }).exec();
    if (!verificationToken) {
        return res.status(400).send("Invalid email validation token");
    }

    await User.updateOne({userId: verificationToken.userId}, {email_verified: true}).exec();
    res.sendStatus(200);
}

interface PostChangePasswordRequestBody {
    userId: ObjectId
    newPassword: string
}

export const postChangePassword = async (req: Request, res: Response) => {
    const body: PostChangePasswordRequestBody = req.body;
    const passwordHash = await bcrypt.hash(body.newPassword, 10);
    User.updateOne({"_id": body.userId}, {"passwordHash": passwordHash});
    res.sendStatus(200);
}

interface PostResetPasswordRequestBody {
    email: string
}

export const PostResetPassword = async (req: Request, res: Response) => {
    const body: PostResetPasswordRequestBody = req.body;
    const user = await User.findOne({"email": body.email}).exec();
    if (!user) {
        return res.status(400).send("There is no user with the given email");
    }

    const newPassword = crypto.randomBytes(constants.DEFAULT_PASSWORD_SIZE_IN_BYTES).toString("hex");
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = newPasswordHash;
    user.save();
    res.sendStatus(200);
}