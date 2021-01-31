import express from "express"
import dotenv from "dotenv"
import mongoose from "mongoose"
import * as controller from "./controllers/authController"
import auth from "./controllers/auth"

// Load the environment variables
dotenv.config();

mongoose.connect(`mongodb://${process.env.DATABASE_IP}:${process.env.DATABASE_PORT}/${process.env.DATABASE}`,
        { useUnifiedTopology: true, useNewUrlParser: true, useCreateIndex: true });
mongoose.connection.on('error', console.error.bind(console, 'Connection error:'));        
mongoose.connection.once('open', function() {
    console.log("Database connection established");
});

const app = express();

app.use(express.json());

app.post("/signup", controller.postSignup);
app.post("/login", controller.postLogin);
app.post("/verifyEmail", controller.postVerifyEmail);
app.post("/resetPassword", controller.PostResetPassword);
app.post("/refresh", auth, controller.postRefresh);
app.post("/changePassword", auth, controller.postChangePassword);

app.listen(process.env.PORT, () => {
    console.log("Server started");
});
