import nodemailer from "nodemailer"
import mails from "../config/mails.json"
import dotenv from "dotenv"

dotenv.config();

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT) || 0,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    }
});

export async function sendVerificationEmail(email: string, token: string): Promise<void> {
    await transporter.sendMail({
        from: mails.from,
        to: email,
        subject: mails.verifyEmail.subject,
        html: mails.verifyEmail.html + mails.verifyEmail.url + token
    });
}

export async function sendResetPasswordEmail(email: string, token: string): Promise<void> {
    await transporter.sendMail({
        from: mails.from,
        to: email,
        subject: mails.resetPassword.subject,
        html: mails.resetPassword.html + mails.resetPassword.url + token
    });
}

