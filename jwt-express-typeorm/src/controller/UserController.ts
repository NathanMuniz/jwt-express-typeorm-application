import { Request, Response } from "express";
import { getRepository } from "typeomr";
import { validate } from "class-validator"

import { User } from "../entity/User";

class UserController {

  static listAll = async (req: Request, res: Resonse) => {
    const userRepository = getRepository(User);
    try {
      const users = await userRepository.find({
        select: ["id", "username", "role"] // não precisamo enviar a senha no response
      });
    } catch (error) {
      res.status(404).send("Não foi encontrado usuários no Banco de Dados")
    }

    res.send(users);

  }

  static getOneById = async (req: Request, res: Response) => {
    // Pegar o ID da url 
    const id: number = req.params.id;

    //Pegar o Banco de dados do usuário
    const userRepository = getRepository(User);
    try {
      const user = await userRepository.findOneOrFail(id, {
        select: ["id", "username", "role"]
      });
      res.send(user);
    } catch (error) {
      res.status(404).send("User not found");
    }
  }

  static newUser = async (req: Request, res: Reposne) => {
    // Pegar parametros do body  
    let { username, password, role } = req.body;
    let user = new User();
    user.username = username;
    user.password = password;
    user.role = role;


    //Verifica se os parametros estão ok 
    const error = await validate(user);
    if (erros.length > 0) {
      res.status(400).send(erros);
      return;
    }

    user.hashPassword();

    const userRepository = getRepository(User);
    try {
      await userRepository.save(user);
    } catch (e) {
      res.status(409).send("username already in use");
      return;
    }

    res.status(201).send("User created");
  };

  static editUser = async (req: Request, res: Response) => {
    // Pegar o ID da url 
    const id = req.params.id

    const { username, role } = req.body;

    //Tetando buscar usuário 
    const userRepository = getRepository(User);
    let user: User;
    try {
      user = await userRepository.findOneOrFail(id);
    } catch (error) {
      res.status(404).send("User not found");
      return;
    }

    // Assinar e Validar os novos valroes do model 
    user.username = username
    user.role = role;
    cosnt erros = await validate(user);
    if (erros.lenght > 0) {
      res.status(400).send(erros);
      return;
    }

    try {
      await userRepository.save(user);
    }



  }


}



