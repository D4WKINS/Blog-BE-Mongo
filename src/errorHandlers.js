export const errorHandler = (err, req, res, next) => {
    err
      ? res.status(err.status).send(err)
      :res.status(404).send({message:"Not found"})
      ?res.status(err.status).send(err)
      : res.status(500).send({ message: "Something went wrong!" })
  };
  