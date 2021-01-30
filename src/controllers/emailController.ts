import { Request, Response } from "express"

import EmailToken from "../models/emailToken"
import User from "../models/user"

interface PostValidateEmailRequestQuery extends qs.ParsedQs {
    token: string
}

export const postValidateEmail = async (req: Request<{}, {}, {}, PostValidateEmailRequestQuery>, res: Response) => {
    const query = req.query;
    // TODO: get userId from access token
    const emailToken = await EmailToken.findOneAndDelete({ token: query.token }).exec();
    if (!emailToken) {
        return res.status(400).send("Invalid email validation token");
    }

    await User.updateOne({userId: emailToken.userId}, {email_verified: true}).exec();
    res.sendStatus(200);
}