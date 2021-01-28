import { Request, Response, NextFunction } from "express"
import User from "../models/user"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import crypto from "crypto"

const TOKEN_DURATION = 15 * 60 * 1000;

interface SignupRequestBody {
    email: string
    username: string
    password: string
}

export const postSignup = async (req: Request<{}, {}, SignupRequestBody>, res: Response, next: NextFunction) => {
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

export const postLogin = async (req: Request, res: Response, next: NextFunction) => {
    const body: LoginRequestBody = req.body;
    const user = await User.findOne({ username: body.username }).exec();
    if (!user) {
        return res.status(400).send("A user with the given username doesn't exist");
    }
    if (!await bcrypt.compare(body.password, user.passwordHash)) {
        return res.status(400).send("Wrong password");
    }
    
    const payload = {
        username: user.username,
        expiration: Date.now() + TOKEN_DURATION
    }
    // Create the access and refresh tokens
    const accessToken = jwt.sign(payload, "sabahci_kahvesi");
    const refreshToken = crypto.randomBytes(64).toString("hex");
    user.accessToken = accessToken;
    user.refreshToken = refreshToken;
    await user.save();

    const responseJson: LoginResponseBody = { accessToken, refreshToken };
    res.status(200).json(responseJson);
}

interface RefreshRequestBody {
    refreshToken: string
}

export const postRefresh = async (req: Request, res: Response, next: NextFunction) => {
    const body: RefreshRequestBody = req.body;
    const user = await User.findOne({ refreshToken: body.refreshToken }).exec();
    if (!user) {
        return res.status(400).send("Invalid refresh token");
    }
       
}

function createNewTokens(username: string): {accessToken: string, refreshToken: string} {
    
}

