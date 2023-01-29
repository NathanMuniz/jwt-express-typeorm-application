import { Request, Response, NextFunction } from "express";
import * as jwt from "jsonwebtoken";
import config from "../config/config";

export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
  // Pegando jwt do header
  const token = <string>req.headers["auth"];
  let jwtPayload;

  //Try to validate the token and get data
  try {
    jwtPayload = <any>jwt.verify(token, config.jwtSecret);
    res.locals.jwtPayload = jwtPayload;
  } catch (error) {
    ///Se o token não for válido, responder com 401 (unauthorized)
    res.status(401).send();
    return;
  }

  //O token é válido por 1h
  //Iremos enviar um novo token a cada request
  const { userId, username } = jwtPayload;
  const newToken = jwt.sign({ userId, username }, config.jwtSecret, {
    expiresIn: "1h"
  });
  res.setHeader("token", newToken);

  //Chama o próximo middleware
  next();
};
