import { ObjectId } from "mongoose"
import jwt from "jsonwebtoken"
import crypto from "crypto"
import constants from "../config/constants.json"

interface IToken {
    userId: ObjectId,
}

export function generateAccessToken(userId: ObjectId): string {
    const payload: IToken = {
        userId: userId,
    } 
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {expiresIn: constants.TOKEN_DURATION_IN_SECONDS});
}

export function verifyAccessToken(token: string): ObjectId {
    //TODO: what happens when the token is invalid or expired ?
    const payload = <IToken> jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    return payload.userId;
}

export function generateRefreshToken(): string {
    return crypto.randomBytes(constants.REFRESH_TOKEN_SIZE_IN_BYTES).toString("hex");
}