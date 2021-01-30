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

const EmailToken = mongoose.model<IEmailToken>("EmailToken", EmailTokenSchema);
export default EmailToken