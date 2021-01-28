import mongoose from "mongoose"
import bcrypt from "bcrypt"

export interface IUser extends mongoose.Document {
    email: string,
    email_verified: boolean,
    username: string,
    passwordHash: string,
}

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    email_verified: {
        type: Boolean,
        default: false,
    },
    username: {
        type: String,
        required: true,
        unique: true,
    },
    passwordHash: {
        type: String,
        required: true,
    }
});

UserSchema.methods.isValidPassword = async function (this: IUser, password: string) {
    const compare = await bcrypt.compare(password, this.passwordHash);
    return compare;
}

export const User = mongoose.model<IUser>("User", UserSchema);