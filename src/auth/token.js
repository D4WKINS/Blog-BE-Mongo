import createHttpError from "http-errors"
import { verifyJWT } from "./tools.js"
import UserModel from "../services/users/schema.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // 1. Check if Authorization header is received, if it is not --> trigger an error (401)

  console.log(req.cookies)

  if (!req.cookies.accessToken) {
    next(createHttpError(401, "Please provide credentials in Cookies!"))
  } else {
    try {
      // 2. Extract the token from the Authorization header (authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTUyZjMzNzdhNWVlYmRlMDhkZThhZjkiLCJpYXQiOjE2MzI5MDU3MTN9.FL17SFz1zSGXbMnsLNxbFrnlgCxU8-FtaTnxbiQr-XM)

      const token = req.cookies.accessToken

      // 3. Verify token, if it goes fine we'll get back the payload ({_id: "oijoij12i3oj23"}), otherwise an error is being thrown by the jwt library
      const decodedToken = await verifyJWT(token)
      console.log(decodedToken)

      // 4. Find the user in db by id and attach him to req.user
      const user = await UserModel.findById(decodedToken._id)

      if (user) {
        req.user = user
        next()
      } else {
        next(createHttpError(404, "User not found!"))
      }
    } catch (error) {
      console.log(error)
      next(createHttpError(401, "Token not valid!"))
    }
  }
}

export const basicAuthMiddleware = async (req, res, next) => {
  // 1. Check if Authorization header is received, if it is not --> trigger an error (401)

  console.log(req.headers)

  if (!req.headers.authorization) {
    next(createError(401, "Please provide credentials in the Authorization header!"))
  } else {
    // 2. Split and Decode base64 and extract credentials from the Authorization header ( base64 --> string)

    const decoded = atob(req.headers.authorization.split(" ")[1])
    console.log(decoded)

    const [email, password] = decoded.split(":")
    // 3. Check the validity of the credentials (find the user in db via email, and compare plainPW with the hashed one), if they are not ok --> trigger an error (401)
    const user = await UserModel.checkCredentials(email, password)
    if (user) {
      // 4. If credentials are valid we proceed to what is next (another middleware or route handler)
      req.user = user
      next()
    } else {
      next(createError(401, "Credentials are not correct!"))
    }
  }
}
