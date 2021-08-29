import createError from "http-errors"
import atob from "atob" //atob() decodes a base64 encoded string

import UserModel from "../services/users/schema.js"
import { verifyJWT } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // 1. Check if Authorization header is received, if it is not --> trigger an error (401)
  console.log(req.headers)
  if (!req.headers.authorization) {
    next(createError(401, "Please provide credentials in the Authorization header!"))
  } else {
    // 2. Extract the token from the authorization header (authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTI0Yjg2OTAwNTk3ZTZkMGNkMmI3Y2UiLCJpYXQiOjE2Mjk4ODA5NTgsImV4cCI6MTYzMDQ4NTc1OH0.wznk3kWrfwSXn5gike8SIKozrR-ppJEn85ypSVXYuTc)

    try {
      const token = req.headers.authorization.replace("Bearer ", "")

      // 3. Verify token

      const decodedToken = await verifyJWT(token)

      // 4. Find the user in db by id

      const user = await UserModel.findById(decodedToken._id)

      if (user) {
        req.user = user
        next()
      } else {
        next(createError(404, "User not found!"))
      }
    } catch (error) {
      next(createError(401, "Token Expired!"))
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
