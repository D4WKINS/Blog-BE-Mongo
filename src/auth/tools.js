import jwt from "jsonwebtoken"
import { promisify } from "util"

import UserModel from "../services/users/schema.js"

export const JWTAuthenticate = async user => {
  // 1. given the user ==> generate the tokens with user._id as payload
  const accessToken = await generateJWT({ _id: user._id })
  const refreshToken = await generateRefreshJWT({ _id: user._id })

  // 2. save refresh token in db

  user.refreshToken = refreshToken

  await user.save()

  return { accessToken, refreshToken }
}

const generateJWT = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" }, (err, token) => {
      if (err) reject(err)
      resolve(token)
    })
  )

const generateRefreshJWT = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: "1 week" }, (err, token) => {
      if (err) reject(err)
      resolve(token)
    })
  )

// generateJWT()
//   .then(token => console.log(token))
//   .catch(err => console.log(err))

export const verifyJWT = token =>
  new Promise((resolve, reject) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if (err) reject(err)
      resolve(decodedToken)
    })
  )

const verifyRefreshJWT = token =>
  new Promise((resolve, reject) =>
    jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, decodedToken) => {
      if (err) reject(err)
      resolve(decodedToken)
    })
  )

// const promisifiedJWTSign = promisify(jwt.sign)

// promisifiedJWTSign(payload, ).then()

export const refreshTokens = async actualRefreshToken => {
  try {
    // 1. Is the actual refresh token still valid?

    const decoded = await verifyRefreshJWT(actualRefreshToken)

    // 2. If the token is valid we are going to find the user in db

    const user = await UserModel.findById(decoded._id)

    if (!user) throw new Error("User not found")

    // 3. Once we have the user we can compare actualRefreshToken with the one stored in db

    if (actualRefreshToken === user.refreshToken) {
      // 4. If everything is fine we can generate the new pair of tokens

      const { accessToken, refreshToken } = await JWTAuthenticate(user)
      return { accessToken, refreshToken }
    } else {
    }
  } catch (error) {
    throw new Error("Token not valid!")
  }
}
