import createHttpError from "http-errors"
import jwt from "jsonwebtoken"
import UserModel from "../services/users/schema.js"

export const JWTAuthenticate = async user => {
  // 1. Given the user ==> generate the token with user._id as payload

  const accessToken = await generateJWT({ _id: user._id })
  console.log(accessToken)
  const refreshToken = await generateRefreshJWT({ _id: user._id })

  // 2. Save refresh token in db
  user.refreshToken = refreshToken

  await user.save()
  return { accessToken, refreshToken }
}

const generateJWT = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_SECRET, (err, token) => {
      if (err) reject(err)
      resolve(token)
    })
  )

// generateJWT(1221321)
//   .then(token => console.log(token))
//   .catch(err => console.log(err))

// try {
//   const token = await generateJWT(12312312)
// } catch (error) {
//   console.log(error)
// }

export const verifyJWT = token =>
  new Promise((resolve, reject) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if (err) reject(err)
      resolve(decodedToken)
    })
  )

const generateRefreshJWT = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: "1 week" }, (err, token) => {
      if (err) reject(err)
      resolve(token)
    })
  )

const verifyRefreshJWT = token =>
  new Promise((resolve, reject) =>
    jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, decodedToken) => {
      if (err) reject(err)
      resolve(decodedToken)
    })
  )

// verifyJWT("o1ij23oi21j3o21j3oj21io3").then(decodedToken => console.log(decodedToken))

export const refreshTokens = async actualRefreshToken => {
  // 1. Is the actual refresh token valid (exp date and integrity)?

  const decodedRefreshToken = await verifyRefreshJWT(actualRefreshToken)

  // 2. If the token is valid we are going to find the user in db

  const user = await UserModel.findById(decodedRefreshToken._id)

  if (!user) throw new Error("User not found!")

  // 3. We need to compare actual refresh token with the one found in db

  if (user.refreshToken === actualRefreshToken) {
    // 4. If everything is fine we can generate a new pair of tokens
    const { accessToken, refreshToken } = await JWTAuthenticate(user)

    return { accessToken, refreshToken }
  } else {
    throw createHttpError(401, "Refresh Token not valid!")
  }
}
