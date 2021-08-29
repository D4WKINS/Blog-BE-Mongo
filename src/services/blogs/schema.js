import mongoose from "mongoose";
import Authors from "../users/schema.js"

const CommentSchema = new mongoose.Schema(
  {
    text: { type: String, required: true },
    likes: {
        default: [],
        type: [
          {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
          },
        ],
      },
    rate: {
      type: Number,
      min: [1, "Rate must be min 1"],
      max: [5, "Rate can be max 5"],
      default: 5,
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User",
    },
  },
  { timestamps: true }
);

const schema = new mongoose.Schema(
  {
    category: { type: String, required: true },
    title: { type: String, required: true },
    cover: { type: String, required: true },
    readTime: {
      value: { type: Number, required: true },
      unit: { type: String, required: true },
    },
    comments: { default: [], type: [CommentSchema] },
    likes: {
      default: [],
      type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
      ],
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User",
    },
    content: { type: String, required: true },
  },
  { timestamps: true }
);

export default mongoose.model("Blog", schema);

schema.pre("save", async function (done) {
  try {
    const isExist = await Authors.findById(this.author);
    if (isExist) {
      done();
    } else {
      const error = new Error("this author does not exist");
      error.status = 400;
      done(error);
    }
  } catch (error) {
    done(error);
  }
})