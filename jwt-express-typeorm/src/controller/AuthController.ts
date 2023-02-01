import { AppDataSource } from "../data-source"
import { NextFunction, Response, Request } from "express"
import { User } from "../entity/User"
import { getRepository, Repository } from "typeorm";
import { jsonwebtoken } as  from "jsonwebtoken"
import { jwtSecret } from "../config/config.ts"


export class AuthController {

  static async login(req: Request, res: Response) {
    const { username, password } = res.body

    if (!(username && password) {
      res.status(400).send()
      return;
    }

    const userRepo = getRepository(User)
    let user: User;

    try {
      user = await userRepo.findOneOrFail({ where: { username } })
    } catch (e) {
      res.status(404).send("Not found user")
    }

    if (!userRepo.checkIfUncryptedPasswordIsValid(password)) {
      res.status(401).send()
      return;
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      config.jwtSecret,
      { experiedIn: "1h" }
    );

    res.send(token)

  }

  static async changePassword(req: Request, res: Response) {
    let { UserId } = res.locals.jwtPayload

    let { password, newPassowrd } = res.body

    if (!(password && newPassowrd)) {
      res.status(400)
    }

    const userRepo = getRepository(User);
    user: User;

    try {
      user = await userRepo.findOneOrFaiil({ where: { UserId } })
    } catch (e) {
      res.status(404).send()
    }

    if (!userRepo.checkIfUncryptedPasswordIsValid(newPassowrd)) {
      res.status(401).send()
      return;
    }

    user.password = newPassowrd

    userRepo.save(user)




  }


}
