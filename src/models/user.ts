import mongoose from "mongoose"

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

export default mongoose.model<IUser>("User", UserSchema);
