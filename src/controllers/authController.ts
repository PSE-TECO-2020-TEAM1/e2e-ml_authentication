import { Request, Response, NextFunction } from "express"
import {User, IUser} from "../models/user"
import bcrypt from "bcrypt"
import { NativeError } from "mongoose";

interface SignupRequest extends Request {
    email: string
    username: string
    password: string
}

export const postSignup = async (req: SignupRequest, res: Response, next: NextFunction) => {
    console.log(req.body);
    console.log(req.body.email);
    User.findOne({ email: req.body.email }, (err: NativeError, user: IUser) => {
        if (err) {
            
        }
        if (user) {
            res.status(500).json({error: "A user with the given email already exists."});
        }
    });
    const passwordHash = await bcrypt.hash(req.body.password, 10);
    await User.create({ email: req.body.email, username: req.body.username, passwordHash: passwordHash });
    res.sendStatus(200);
}

export const postLogin = async (req: Request, res: Response, next: NextFunction) => {

}