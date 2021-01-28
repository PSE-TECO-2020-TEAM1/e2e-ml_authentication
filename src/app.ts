import express from "express"
import mongoose from "mongoose"
import * as controller from "./controllers/authController"

mongoose.connect('mongodb://0.0.0.0:27017/gamestop');
mongoose.connection.on('error', error => console.log(error));

const app = express();

app.use(express.json());

app.post("/signup", controller.postSignup);
app.post("/login", controller.postLogin);

app.listen(3131, () => {
    console.log("Server started");
});
