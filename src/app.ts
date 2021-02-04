import express from "express"
import dotenv from "dotenv"
import mongoose from "mongoose"

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

app.listen(process.env.PORT, () => {
    console.log("Server started");
});
