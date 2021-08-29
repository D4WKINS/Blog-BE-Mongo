
import mongoose from 'mongoose';

const schema = new mongoose.Schema({

    name: { type: String, required: true },
    surname: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String },
    role: { type: String, required: true, enum: ["Admin", "User"], default: "User" },
    refreshToken: { type: String },
    googleId: { type: String }
})

const model = mongoose.model('User', schema);

export default model;