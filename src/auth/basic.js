import createHttpError from "http-errors"
import atob from "atob" // to decode base64 strings
import UserModel from "../services/users/schema.js"

export const basicAuthMiddleware = async (req, res, next) => {

  console.log("BASIC AUTH MIDDLEWARE")
  console.log(req.headers)

  // 1. Check if Authorization header is received, if it is not --> trigger an error (401)
  if (!req.headers.authorization) {
    next(createHttpError(401, "Please provide credentials in Authorization header!"))
  } else {
    // 2. If we received the Authorization header we'll need to extract the credentials from the Authorization header (which is in base64, therefore we will need to decode that obtaining normal text)
    const decodedCredentials = atob(req.headers.authorization.split(" ")[1])
    console.log("decoded credentials: ", decodedCredentials)

    const [email, password] = decodedCredentials.split(":") // --> ["diego2@banovaz.com", "diego1234"]

    console.log("EMAIL ", email)
    console.log("PASSWORD ", password)

    // 3. Check the validity of the credentials (find user in db by email, compare received password with hashed pw), if they aren't ok --> trigger an error (401)

    const user = await UserModel.checkCredentials(email, password)

    if (user) {
      // 4. If credentials are valid we can proceed to what is next (another middleware or the route handler)
      req.user = user
      next()
    } else {
      next(createHttpError(401, "Credentials are not correct!"))
    }
  }
}
