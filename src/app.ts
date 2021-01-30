import express from "express"
import dotenv from "dotenv"
import mongoose from "mongoose"
import * as controller from "./controllers/authController"

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
app.post("/refresh", controller.postRefresh);

app.post("/validateEmail", controller.postValidateEmail);

app.listen(process.env.PORT, () => {
    console.log("Server started");
});
