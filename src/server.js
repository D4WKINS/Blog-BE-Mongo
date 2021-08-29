import express from "express";

import cors from "cors";

import listEndpoints from "express-list-endpoints";

import usersRouter from "./services/users/index.js";

import blogsRouter from "./services/blogs/index.js";

import { errorHandler } from "./errorHandlers.js";

import mongoose from "mongoose";

const server = express();

const { PORT, MONGO_CONNECTION_STRING } = process.env;

const whiteList = ["http://localhost:3000"];
const corsOptions = {
  origin: (origin, callback) => {
    if (whiteList.some((allowedUrl) => allowedUrl === origin)) {
      callback(null, true);
    } else {
      const error = new Error("Not allowed by cors!");
      error.status = 403;

      callback(error);
    }
  },
};

server.use(cors(corsOptions));

server.use(express.json());

// server.use(express.static(publicDirectory));

server.use("/user", usersRouter);

server.use("/blogs", blogsRouter);

server.use(errorHandler);

console.table(listEndpoints(server));

server.listen(PORT, async () => {
  try {
    await mongoose.connect(MONGO_CONNECTION_STRING, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`✅ Server is running on ${PORT}  and connected to db`);
  } catch (error) {
    console.log("Db connection is failed ", error);
  }
});

server.on("error", (error) =>
  console.log(`❌ Server is not running due to : ${error}`)
);


