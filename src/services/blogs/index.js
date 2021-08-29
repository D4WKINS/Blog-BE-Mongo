import express from "express";
import Blogs from "./schema.js";
import {
  checkBlogPostSchema,
  checkCommentSchema,
  checkValidationResult,
} from "./validation.js";

const blogsRouter = express.Router();

// get all blogs
blogsRouter.get("/", async (req, res, next) => {
  try {
    const blogs = await Blogs.find({}).populate({
      path: "author",
      select: "name surname avatar",
    });
    res.send(blogs);
  } catch (error) {
    console.log({ error });
    res.send(500).send({ message: error.message });
  }
});

// blogsRouter.get(
//   "/search",
//   checkSearchSchema,
//   checkValidationResult,
//   async (req, res, next) => {
//     try {
//       const { title } = req.query;
//       //regex match ?
//       const filtered = await Blogs.find({ title });
//       res.send(filtered);
//     } catch (error) {
//       res.send(500).send({ message: error.message });
//     }
//   }
// );

// create  blog
blogsRouter.post(
  "/",
  checkBlogPostSchema,
  checkValidationResult,
  async (req, res, next) => {
    try {
      const blog = await new Blogs(req.body).save();
      res.status(201).send(blog);
    } catch (error) {
      console.log(error);
      res.send(500).send({ message: error.message });
    }
  }
);

// get single blogs
// blogsRouter.get("/:id/pdf", async (req, res, next) => {
//   try {
//     const fileAsBuffer = fs.readFileSync(blogsFilePath);

//     const fileAsString = fileAsBuffer.toString();

//     const fileAsJSONArray = JSON.parse(fileAsString);

//     const blog = fileAsJSONArray.find((blog) => blog.id === req.params.id);
//     if (!blog) {
//       res
//         .status(404)
//         .send({ message: `blog with ${req.params.id} is not found!` });
//     }
//     const pdfStream = await generateBlogPDF(blog);
//     res.setHeader("Content-Type", "application/pdf");
//     pdfStream.pipe(res);
//     pdfStream.end();
//   } catch (error) {
//     res.send(500).send({ message: error.message });
//   }
// });

blogsRouter.get("/:id", async (req, res, next) => {
  try {
    const blog = await Blogs.findById(req.params.id).populate({
      path: "author",
      select: "name surname avatar",
    });
    if (!blog) {
      res
        .status(404)
        .send({ message: `blog with ${req.params.id} is not found!` });
    } else {
      res.send(blog);
    }
  } catch (error) {
    res.send(500).send({ message: error.message });
  }
});
blogsRouter.get("/:id/comments", async (req, res, next) => {
  try {
    const blog = await Blogs.findById(req.params.id);
    if (!blog) {
      res
        .status(404)
        .send({ message: `blog with ${req.params.id} is not found!` });
    }
    res.send(blog.comments);
  } catch (error) {
    res.send(500).send({ message: error.message });
  }
});

// delete  blog
blogsRouter.delete("/:id", async (req, res, next) => {
  try {
    const blog = await Blogs.findById(req.params.id);
    if (!blog) {
      res
        .status(404)
        .send({ message: `blog with ${req.params.id} is not found!` });
    } else {
      await Blogs.findByIdAndDelete(req.params.id);
      res.status(204).send();
    }
  } catch (error) {
    res.send(500).send({ message: error.message });
  }
});

//  update blog
blogsRouter.put("/:id", async (req, res, next) => {
  try {
    const updated = await Blogs.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    res.send(updated);
  } catch (error) {
    res.send(500).send({ message: error.message });
  }
});

blogsRouter.put("/:id/like", async (req, res, next) => {
  try {
    const { id } = req.body;
    const isLiked = await Blogs.findOne({ _id: req.params.id, likes: id });
    if (isLiked) {
      await Blogs.findByIdAndUpdate(req.params.id, { $pull: { likes: id } });
      res.send("UNLIKED");
    } else {
      await Blogs.findByIdAndUpdate(req.params.id, { $push: { likes: id } });
      res.send("LIKED");
    }
  } catch (error) {
    res.send(500).send({ message: error.message });
  }
});

blogsRouter.put(
  "/:id/comment",
  checkCommentSchema,
  checkValidationResult,
  async (req, res, next) => {
    try {
      const blog = await Blogs.findById(req.params.id);
      if (!blog) {
        res
          .status(404)
          .send({ message: `blog with ${req.params.id} is not found!` });
      } else {
        console.log(req.body);
        await Blogs.findByIdAndUpdate(
          req.params.id,
          {
            $push: {
              comments: req.body,
            },
          },
          { new: true }
        );
        res.status(204).send();
      }
    } catch (error) {
      console.log(error);
      res.send(500).send({ message: error.message });
    }
  }
);

blogsRouter.put("/:id/comment/:commentId", async (req, res, next) => {
  try {
    const blog = await Blogs.findById(req.params.id);
    if (!blog) {
      res
        .status(404)
        .send({ message: `blog with ${req.params.id} is not found!` });
    } else {
      const commentIndex = blog.comments.findIndex(
        (comment) => comment._id.toString() === req.params.commentId
      );
      if (commentIndex === -1) {
        res.status(404).send({
          message: `comment with ${req.params.commentId} is not found!`,
        });
      } else {
        blog.comments[commentIndex] = {
          ...blog.comments[commentIndex]._doc,
          ...req.body,
        };
        await blog.save();
        res.status(204).send();
      }
    }
  } catch (error) {
    console.log(error);
    res.send(500).send({ message: error.message });
  }
});

blogsRouter.delete("/:id/comment/:commentId", async (req, res, next) => {
  try {
    const blog = await Blogs.findById(req.params.id);
    if (!blog) {
      res
        .status(404)
        .send({ message: `blog with ${req.params.id} is not found!` });
    } else {
      await Blogs.findByIdAndUpdate(
        req.params.id,
        {
          $pull: {
            comments: { _id: req.params.commentId },
          },
        },
        { new: true }        );
      res.status(204).send();
    }
  } catch (error) {
    console.log(error);
    res.send(500).send({ message: error.message });
  }
});

// blogsRouter.put("/:id/cover", parseFile.single("cover"), async (req, res, next) => {
//   try {
//     const fileAsBuffer = fs.readFileSync(blogsFilePath);

//     const fileAsString = fileAsBuffer.toString();

//     let fileAsJSONArray = JSON.parse(fileAsString);

//     const blogIndex = fileAsJSONArray.findIndex(
//       (blog) => blog.id === req.params.id
//     );
//     if (!blogIndex == -1) {
//       res
//         .status(404)
//         .send({ message: `blog with ${req.params.id} is not found!` });
//     }
//     const previousblogData = fileAsJSONArray[blogIndex];
//     const changedblog = {
//       ...previousblogData,
//       cover: req.file.path,
//       updatedAt: new Date(),
//       id: req.params.id,
//     };
//     fileAsJSONArray[blogIndex] = changedblog;

//     fs.writeFileSync(blogsFilePath, JSON.stringify(fileAsJSONArray));
//     res.send(changedblog);
//   } catch (error) {
//     console.log(error);
//     res.send(500).send({ message: error.message });
//   }
// });

export default blogsRouter;
