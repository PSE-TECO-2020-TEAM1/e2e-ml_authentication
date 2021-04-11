import { Request, Response } from "express"
import bcrypt from "bcrypt"
import crypto from "crypto"
import { body, query, ValidationChain } from "express-validator"

import * as auth from "./auth"
import User from "../models/user"
import { EmailVerificationToken } from "../models/emailToken"
import constants from "../config/constants.json"
import * as email from "./email"

interface RequestValidator {
    postSignup: Array<ValidationChain>,
    postLogin: Array<ValidationChain>,
    postRefresh: Array<ValidationChain>,
    postVerifyEmail: Array<ValidationChain>,
    postChangePassword: Array<ValidationChain>,
    postResetPassword: Array<ValidationChain> 
}

export let validate: RequestValidator = {
    postSignup: [],
    postLogin: [],
    postRefresh: [],
    postVerifyEmail: [],
    postChangePassword: [],
    postResetPassword: []
}


interface SignupRequestBody {
    email: string
    username: string
    passwordHash: string
}
validate.postSignup = [
    body("email").exists().isEmail(),
    body("username").exists().isString(),
    body("passwordHash").exists().isString()
]

export const postSignup = async (req: Request, res: Response) => {
    const body: SignupRequestBody = req.body;
    // Check if the email is unique
    let user = await User.findOne({ email: body.email }).exec();
    if (user) {
        return res.status(400).json("A user with the given email already exists");
    }
    // Check if the username is unique 
    user = await User.findOne({username: body.username }).exec();
    if (user) {
        return res.status(400).json("A user with the given username already exists");
    }
    // Create new user
    const passwordHash = await bcrypt.hash(body.passwordHash, 10);
    const newUser = await User.create({ email: body.email, username: body.username, passwordHash: passwordHash });
    // Send email validation token
    const verificationToken = crypto.randomBytes(constants.EMAIL_TOKEN_SIZE_IN_BYTES).toString("hex");
    await EmailVerificationToken.create({ userId: newUser._id, token: verificationToken});
    // await email.sendVerificationEmail(body.email, verificationToken)

    res.status(200).json("OK");
}

interface LoginRequestBody {
    username: string
    passwordHash: string
}
validate.postLogin = [
    body("username").exists().isString(),
    body("passwordHash").exists().isString()
]

interface LoginResponseBody {
    accessToken: string,
    refreshToken: string
}

export const postLogin = async (req: Request, res: Response) => {
    const body: LoginRequestBody = req.body;
    const user = await User.findOne({ username: body.username }).exec();
    if (!user) {
        return res.status(400).json("A user with the given username doesn't exist");
    }
    if (!await bcrypt.compare(body.passwordHash, user.passwordHash)) {
        return res.status(400).json("Wrong password");
    }

    const accessToken = auth.generateAccessToken(user._id);
    const refreshToken = auth.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save();

    const responseJson: LoginResponseBody = { accessToken, refreshToken };
    res.status(200).json(responseJson);
}

interface RefreshRequestBody {
    userId: string,
    refreshToken: string
}
validate.postRefresh = [
    body("userId").exists().isString(),
    body("refreshToken").exists().isString()
]

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
        return res.status(401).json("Unauthorized")
    }

    const newAccessToken = auth.generateAccessToken(body.userId);
    const newRefreshToken = auth.generateRefreshToken();
    user.refreshToken = newRefreshToken;
    await user.save();

    const responseJson: RefreshResponseBody = { newAccessToken, newRefreshToken };
    res.status(200).json(responseJson);
}

interface PostVerifyEmailRequestQuery extends qs.ParsedQs {
    token: string
}
validate.postVerifyEmail = [
    query("token").exists().isString()
]

export const postVerifyEmail = async (req: Request<{}, {}, {}, PostVerifyEmailRequestQuery>, res: Response) => {
    const query = req.query;
    // TODO: get userId from access token
    const verificationToken = await EmailVerificationToken.findOneAndDelete({ token: query.token }).exec();
    if (!verificationToken) {
        return res.status(400).json("Invalid email validation token");
    }

    await User.updateOne({userId: verificationToken.userId}, {email_verified: true}).exec();
    res.status(200).json("OK");
}

interface PostChangePasswordRequestBody {
    userId: string
    newPassword: string
}
validate.postChangePassword = [
    body("userId").exists().isString(),
    body("newPassword").exists().isString()
]

export const postChangePassword = async (req: Request, res: Response) => {
    const body: PostChangePasswordRequestBody = req.body;
    const passwordHash = await bcrypt.hash(body.newPassword, 10);
    await User.updateOne({"_id": body.userId}, {"passwordHash": passwordHash}).exec();
    res.status(200).json("OK");
}

interface PostResetPasswordRequestBody {
    email: string
}
validate.postResetPassword = [
    body("email").exists().isEmail()
]

export const PostResetPassword = async (req: Request, res: Response) => {
    const body: PostResetPasswordRequestBody = req.body;
    const user = await User.findOne({"email": body.email}).exec();
    if (!user) {
        return res.status(400).json("There is no user with the given email");
    }

    const newPassword = crypto.randomBytes(constants.DEFAULT_PASSWORD_SIZE_IN_BYTES).toString("hex");
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = newPasswordHash;
    await user.save();
    res.status(200).json("OK");
}
