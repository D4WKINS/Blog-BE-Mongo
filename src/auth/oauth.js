import passport from "passport"
import GoogleStrategy from "passport-google-oauth20"
import UserModel from "../services/users/schema.js"
import { JWTAuthenticate } from "./tools.js"

const googleStrategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_SECRET,
    callbackURL: "http://localhost:3001/users/googleRedirect", // this needs to match the redirect url configured on console.cloud.google.com
  },
  async (accessToken, refreshToken, profile, passportNext) => {
    try {
      // We are going to receive profile info from Google
      console.log(profile)

      // 1. Check if this user is already in db or not, if it is not we are going to create a record
      const user = await UserModel.findOne({ googleId: profile.id })

      if (user) {
        // 2. If user is already there we are going to create the tokens for him/her
        const tokens = await JWTAuthenticate(user)
        passportNext(null, { tokens })
      } else {
        // 3. If user is not there we are going to create a record and the create the tokens for him/her

        const newUser = {
          name: profile.name.givenName,
          surname: profile.name.familyName,
          email: profile.emails[0].value,
          role: "User",
          googleId: profile.id,
        }

        const createdUser = new UserModel(newUser)

        const savedUser = await createdUser.save()
        const tokens = await JWTAuthenticate(savedUser)
        passportNext(null, { user: savedUser, tokens })
      }
    } catch (error) {
      passportNext(error)
    }
  }
)

passport.serializeUser(function (user, passportNext) {
  // REQUIRED to have req.user
  passportNext(null, user)
})

export default googleStrategy
