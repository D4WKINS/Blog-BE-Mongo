import GoogleStrategy from "passport-google-oauth20"
import passport from "passport"
import UserModel from "../services/users/schema.js"
import { JWTAuthenticate } from "./tools.js"

const googleStrategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_OAUTH_ID,
    clientSecret: process.env.GOOGLE_OAUTH_SECRET,
    callbackURL: `${process.env.API_URL}:${process.env.PORT}/users/googleRedirect`,
  },
  async (accessToken, refreshToken, profile, passportNext) => {
    try {
      // We are receiving some profile information from Google
      console.log(profile)

      // 1. Check if user is already in db or not.

      const user = await UserModel.findOne({ googleId: profile.id })

      if (user) {
        // 2. If user was already there we are creating the tokens for him/her

        const tokens = await JWTAuthenticate(user)

        passportNext(null, { tokens })
      } else {
        // 3. If it is not we are creating a new record and then we are creating the tokens for him/her
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
      console.log(error)
      passportNext(error)
    }
  }
)

passport.serializeUser(function (user, passportNext) {
  passportNext(null, user) // MANDATORY. This attaches stuff to req.user
})

export default googleStrategy
