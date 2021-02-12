import { Request, Response, NextFunction, Router } from "express"

import * as controller from "../controllers/authController"
import { Authenticate } from "../controllers/auth"
import { validationResult } from "express-validator"

let router = Router();

const validated = (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({error: errors.array()});
    }
    next();
}

router.post("/signup", controller.validate.postSignup, validated, controller.postSignup);
router.post("/login", controller.validate.postLogin, validated, controller.postLogin);
router.post("/verifyEmail", controller.validate.postVerifyEmail, validated, controller.postVerifyEmail);
router.post("/resetPassword", controller.validate.postResetPassword, validated, controller.PostResetPassword);
router.post("/refresh", Authenticate, controller.validate.postRefresh, validated, controller.postRefresh);
router.post("/changePassword", Authenticate, controller.validate.postChangePassword, validated, controller.postChangePassword);

export default router;