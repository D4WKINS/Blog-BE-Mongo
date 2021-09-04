import express from "express"
import createError from "http-errors"
import passport from "passport"
import UserModel from "./schema.js"
import { basicAuthMiddleware, JWTAuthMiddleware } from "../../auth/middlewares.js"
import { adminOnly } from "../../auth/admin.js"
import { JWTAuthenticate, refreshTokens } from "../../auth/tools.js"

const usersRouter = express.Router()

usersRouter.post("/register", async (req, res, next) => {
  try {
    const newUser = new UserModel(req.body)
    const { _id } = await newUser.save()

    res.status(201).send({ _id })
  } catch (error) {
      console.log(error)
    // next(error)
  }
})
usersRouter.get("/", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const users = await UserModel.find()
    res.send(users)
  } catch (error) {
    next(error)
  }
})
usersRouter.get("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    res.send(req.user)
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    req.user.name = "Whatever" // modify req.user with the fields coming from req.body
    await req.user.save()

    res.send()
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    // await UserModel.findByIdAndDelete(req.user._id)

    await req.user.deleteOne()
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/:userID", JWTAuthMiddleware, adminOnly, async (req, res, next) => {
  res.send()
})

usersRouter.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body // get the email and the password from the body of the request
    // 1. verify credentials
    const user = await UserModel.checkCredentials(email, password) // check if the user exists and if the password is correct

    if (user) {
      // 2. Generate tokens if credentials are ok
      const { accessToken, refreshToken } = await JWTAuthenticate(user)
      // 3. Send tokens back as a response
      res.send({ accessToken, refreshToken })
    } else {
      next(createError(401, "Credentials not valid!"))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/refreshToken", async (req, res, next) => {
  try {
    const { actualRefreshToken } = req.body

    // 1. Check the validity (and the integrity) of the refresh token, if everything is ok we can create a new pair of access and refresh token
    const { accessToken, refreshToken } = await refreshTokens(actualRefreshToken)
    res.send({ accessToken, refreshToken })
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/logout", JWTAuthMiddleware, async (req, res, next) => {
  try {
    req.user.refreshToken = null

    await req.user.save()

    res.send()
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/googleLogin", passport.authenticate("google", { scope: ["profile", "email"] })) // this endpoint is redirecting users to google page

usersRouter.get("/googleRedirect", passport.authenticate("google"), async (req, res, next) => {
  try {
    // res.send(req.user.tokens)

    res.redirect(`http://localhost:3000?accessToken=${req.user.tokens.accessToken}&refreshToken=${req.user.tokens.refreshToken}`)
  } catch (error) {
    next(error)
  }
})

export default usersRouter
