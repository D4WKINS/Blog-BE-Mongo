import express from "express"
import mongoose from "mongoose"
import cors from "cors"
import listEndpoints from "express-list-endpoints"
import passport from "passport"
import cookieParser from "cookie-parser"
import usersRouter from "./services/users/index.js"
import { unauthorizedHandler, forbiddenHandler, catchAllHandler } from "./errorHandlers.js"
import GoogleStrategy from "./auth/oauth.js"

const server = express()
const port = process.env.PORT || 3001

passport.use("google", GoogleStrategy)

// ******************** MIDDLEWARES *************************+

server.use(cors({ origin: "http://localhost:3000", credentials: true })) // no options means Access-Control-Allow-Origin: "*"
server.use(express.json())
server.use(cookieParser())
server.use(passport.initialize())

// ******************** ROUTES ******************************

server.use("/users", usersRouter)

// ********************** ERROR HANDLERS *************************

server.use(unauthorizedHandler)
server.use(forbiddenHandler)
server.use(catchAllHandler)

console.table(listEndpoints(server))

mongoose.connect(process.env.MONGO_CONNECTION)

mongoose.connection.on("connected", () => {
  console.log("Mongo connected!")
  server.listen(port, () => {
    console.log(`Server running on port ${port}`)
  })
})


