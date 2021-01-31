import mongoose from "mongoose"
import bcrypt from "bcrypt"

interface IUser extends mongoose.Document {
    email: string,
    email_verified: boolean,
    username: string,
    passwordHash: string,
    refreshToken: string
}

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    email_verified: {
        type: Boolean,
        required: true,
        default: false
    },
    username: {
        type: String,
        required: true,
        unique: true
    },
    passwordHash: {
        type: String,
        required: true
    },
    refreshToken: {
        type: String
    }
});

UserSchema.methods.isValidPassword = async function (this: IUser, password: string) {
    const compare = await bcrypt.compare(password, this.passwordHash);
    return compare;
}

export default mongoose.model<IUser>("User", UserSchema);
