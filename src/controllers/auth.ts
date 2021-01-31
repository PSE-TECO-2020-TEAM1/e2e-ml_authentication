import * as token from "./token"
import { Request, Response, NextFunction } from "express"

export default async (req: Request, res: Response, next: NextFunction) => {
    let userId;
    try {
        const accessToken = req.headers.authorization.split(' ')[1];
        userId = token.verifyAccessToken(accessToken);
    } catch {
        res.sendStatus(401);
    }

    req.body.userId = userId;
    next();
}