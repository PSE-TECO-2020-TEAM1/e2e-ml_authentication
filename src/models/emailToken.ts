import mongoose, { ObjectId } from "mongoose"

interface IEmailToken extends mongoose.Document {
    userId: ObjectId;
    token: string
}

const EmailTokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Types.ObjectId,
        required: true,
        unique: true
    },
    token: {
        type: String,
        required: true
    }
})

export const EmailVerificationToken = mongoose.model<IEmailToken>("EmailVerificationToken", EmailTokenSchema);
export const ResetPasswordToken = mongoose.model<IEmailToken>("ResetPasswordToken", EmailTokenSchema);