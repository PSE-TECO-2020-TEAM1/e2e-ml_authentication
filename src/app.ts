import express from "express"
import dotenv from "dotenv"
import mongoose from "mongoose"

import Router from "./routers/authRouters"
// Load the environment variables
dotenv.config();

mongoose.connect(`mongodb+srv://${process.env.DATABASE_USER}:${process.env.DATABASE_PASS}@${process.env.DATABASE_IP}/${process.env.DATABASE}?retryWrites=true&w=majority`,
    { useUnifiedTopology: true, useNewUrlParser: true, useCreateIndex: true }).catch(error => {
        console.log("Database connection failed");
    }
    );
mongoose.connection.once('open', function () {
    console.log("Database connection established");
});

const app = express();

app.use(express.json());

app.use("/auth", Router);

app.listen(process.env.PORT, () => {
    console.log("Server started");
});
