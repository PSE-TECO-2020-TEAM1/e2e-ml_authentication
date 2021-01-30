import { ObjectId } from "mongoose"
import crypto from "crypto"
import constants from "../config/constants.json"
import EmailToken from "../models/emailToken"
import User from "../models/user"

export async function sendTokenToEmail(userId: ObjectId, email: string): Promise<void> {
    const token = crypto.randomBytes(constants.EMAIL_TOKEN_SIZE_IN_BYTES).toString("hex");
    await EmailToken.create({ userId: userId, token: token});
    // TODO: send email with the token
}

export async function checkToken(userId: ObjectId, token: string): Promise<boolean> {
    const result = await EmailToken.deleteOne({ userId: userId, token: token}).exec();
    if (!result.deletedCount) {
        return false;
    }

    User.updateOne({ _id: userId }, { email_verified: true }).exec();
    return true;
}