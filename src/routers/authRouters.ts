import { Request, Response, NextFunction, Router } from "express"

import * as controller from "../controllers/authController"
import auth from "../controllers/auth"
import { validationResult } from "express-validator"

export let router = Router()

const validated = (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({error: errors.array()});
    }
    next();
}

router.post("/signup", controller.validate.postSignup, validated, controller.postSignup);
router.post("/login", controller.validate.postLogin, validated, controller.postLogin);
router.post("/verifyEmail", controller.validate.postLogin, validated, controller.postVerifyEmail);
router.post("/resetPassword", controller.validate.postLogin, validated, controller.PostResetPassword);
router.post("/refresh", auth, controller.validate.postLogin, validated, controller.postRefresh);
router.post("/changePassword", auth, controller.validate.postLogin, validated, controller.postChangePassword);