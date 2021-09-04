
import mongoose from 'mongoose';
import bcrypt from 'bcrypt'

const UserSchema = new mongoose.Schema({

    name: { type: String, required: true },
    surname: { type: String, required: true },
    dateOfBirth: { type: Date, required: true },
    avatar: { type: String },
    email: { type: String, required: true },
    password: { type: String },
    role: { type: String, required: true, enum: ["Admin", "User"], default: "User" },
    refreshToken: { type: String },
    googleId: { type: String }

},{
    timestamps: true
})

UserSchema.pre("save", async function (next) {
    // BEFORE saving new user in db, hash the password
    const newUser = this
  
    const plainPW = newUser.password
  
    if (newUser.isModified("password")) {
      newUser.password = await bcrypt.hash(plainPW, 10)
    }
  
    next()
  })

  UserSchema.pre("save", function (done) {
    this.avatar = `https://ui-avatars.com/api/?name=${this.name}+${this.surname}`;
    done();
  });
  
  UserSchema.methods.toJSON = function () {
    // toJSON is called every time express does a res.send
  
    const userDocument = this
  
    const userObject = userDocument.toObject()
  
    delete userObject.password
  
    delete userObject.__v
  
    delete userObject.refreshToken
  
    return userObject
  }
  
  UserSchema.statics.checkCredentials = async function (email, plainPW) {
    // 1. find user in db by email
  
    const user = await this.findOne({ email })
  
    if (user) {
      // 2. if user is found we need to compare plainPW with hashed PW
      const isMatch = await bcrypt.compare(plainPW, user.password)
  
      // 3. return a meaningful response
  
      if (isMatch) return user
      else return null
    } else {
      return null
    }
  }
  
const model = mongoose.model('User', UserSchema);

export default model;