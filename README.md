# Aprendendo a fazer uma completa aplicação REST API, com autenticação JWT e autorização, usando o poder de TypeScript e TypeORM.

## Vamos começar !

Vamos começar usando a ferramenta CLI do TypeORM, que nos permite criar uma nova aplicação base para começarmos. Então precisamos instalar TypeORM e configurar nossa aplicação.

```powershell
# Instalação 
npm install -g typeorm

# Inicializando aplicação
typeorm init --name jwt-express-typeorm --database sqlite --express

# Instalando algumas dependências 
npm install -s helmet cors jsonwebtoken bcryptjs class-validator ts-node-dev

# Instale Type check dependencias
npm install -s @types/bcryptjs @types/body-parser @types/cors @types/helmet @types/jsonwebtoken

```

### Estrutura

 A estrutura inicial de nossa aplicação deve ser assim

- /src
    - /config
        - config.ts
    - /controller
        - AuthController.ts
        - UserController.ts
    - /entity
        - User.ts
    - /middlwares
        - checkJwt.ts
        - checkRole.ts
    - /migration
        - 1579133758-CreateAdminUser.ts
    - /routes
        - auth.ts
        - index.ts
        - user.ts
    - index.ts

### Index.ts

Iremos criar um nova conexão com o banco de dados e iremos inicializar nossa aplicação express. É importante também chamar os middlewares que usaremos (cors, bodyparser e helmet), setar a pasta onde estará nossas rotas e ouvir a porta em que nossa aplicação estará: 3000

```tsx
import "reflect-metadata";
import { createConnection } from "typeorm";
import * as express from "express";
import * as bodyParser from "body-parser";
import * as helmet from "helmet";
import * as cors from "cors";
import routes from "./routes";

//Connects to the Database -> then starts the express
createConnection()
  .then(async connection => {
    // Create a new express application instance
    const app = express();

    // Call midlewares
    app.use(cors());
    app.use(helmet());
    app.use(bodyParser.json());

    //Set all routes from routes folder
    app.use("/", routes);

    app.listen(3000, () => {
      console.log("Server started on port 3000!");
    });
  })
  .catch(error => console.log(error));
```

## Entidade User

O TypeOrm, por padrão já cria uma entidade para o User, porém iremos modificar um pouco o que foi criado. Como estamos trabalhando com ORM, criar um table user se torna muito trivial e fácil, decorator facilita muito nossa vida.

- Principais campos
    - id
    - username
    - password
    - role
    - updateAt
- métodos
    - hashPassword - cripta nossa senha
    - checkIfunencrypetdPasswordIsvALID - verifica se nossa senha não criptada é válida

```tsx
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Unique,
  CreateDateColumn,
  UpdateDateColumn
} from "typeorm";
import { Length, IsNotEmpty } from "class-validator";
import * as bcrypt from "bcryptjs";

@Entity()
@Unique(["username"])
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  @Length(4, 20)
  username: string;

  @Column()
  @Length(4, 100)
  password: string;

  @Column()
  @IsNotEmpty()
  role: string;

  @Column()
  @CreateDateColumn()
  createdAt: Date;

  @Column()
  @UpdateDateColumn()
  updatedAt: Date;

  hashPassword() {
    this.password = bcrypt.hashSync(this.password, 8);
  }

  checkIfUnencryptedPasswordIsValid(unencryptedPassword: string) {
    return bcrypt.compareSync(unencryptedPassword, this.password);
  }
}
```

## Middlewares

Além dos middlewares que importamos, iremos precisar criar outros que nós ajudará a trabalhar com o jwt. Iremos criar nossos middlewares dentro das pasta de middlewares.

**********CheckJwt.ts**********

- Esse middleware será responsável por validar um o token do usuário, e caso seja válido, ele irá criar um novo middleware. Nosso token será válido apenas por 1h, caso tenha passado esse tempo, o usuário terá que assinar um novo token.
    
    Pegaremos nosso Token do headers de nosso request(Esses tokens de autorização ficam na “propriedade” **auth** do header). Caso nosso token não seja uma string, iremos forçar que o retorno desse header seja uma string. E iremos declarar nossa variável Payload (porque iremos usar o try e catch, para assinar ou não ela).
    
    ```tsx
    export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
      // Pegando jwt do header
      const token = <string>req.headers["auth"];
      let jwtPayload;
    };
    ```
    
    ---
    
    Temos que assinar o Payload com o retorno da função jwt.verify, passando nosso token e nossa chave secreta como parâmetros. Esse payload contém os dados do usuário, iremos usar o locals de nosso response para enviar esse payload. Caso ocorra algum erro, iremos enviar o código 401 (não autorizado) e pararemos nosso token por aí.
    
    ```tsx
    export const checkJwt = (req: Request, res: Response, next: NextFunction) => {
      // Pegando jwt do header
      const token = <string>req.headers["auth"];
      let jwtPayload;
    
      // Tentando validar o token e pegar os dados
      try {
        jwtPayload = <any>jwt.verify(token, config.jwtSecret);
        res.locals.jwtPayload = jwtPayload;
      } catch (error) {
        //Se o token não for válido, responder com 401 (unauthorized)
        res.status(401).send();
        return;
      }
    };
    ```
    
    ---
    
    Após validar o token, iremos criar um novo token que inspira em 1h. Para isso iremos pegar o userId e o username do paylod, charemos o método jwt.sing e passaremos os dados, o segredo e quanto tampo nosso token irá durar. Após isso, iremos setar esse novo token no nosso response.
    
    ```tsx
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
    ```
    

******************checkRole******************

- Esse middleware será responsável por verificar se o usuário tem acesso a certas “roles”, certas permissões.
    
    Essa função irá receber uma lista de permissões e retorna umaf unção assincrona que validará se nossa request tem essas permissões.
    
    Iremos busca a ID do usuário que fez o resquest, e buscaremos esse usuário usando o repository, tratando caso não encontre o usuário.
    
    Após buscar o usuário, checaremos se o array de roles autorizados inclui os roles do usuário.
    
    Nosso código ficará assim:
    
    ```tsx
    import { Request, Response, NextFunction } from "express";
    import { getRepository } from "typeorm";
    
    import { User } from "../entity/User";
    
    export const checkRole = (roles: Array<string>) => {
      return async (req: Request, res: Response, next: NextFunction) => {
        //Pega a Id do usuário
        const id = res.locals.jwtPayload.userId;
    
        //Busca o usuário
        const userRepository = getRepository(User);
        let user: User;
        try {
          user = await userRepository.findOneOrFail(id);
        } catch (id) {
          res.status(401).send();
        }
    
        //Verifica se os o array de rols inclui os rols do usuário
        if (roles.indexOf(user.role) > -1) next();
        else res.status(401).send();
      };
    };
    ```
    

## Controllers

******************************AuthController****************************** 

Controller responsável por controlar coisas relacionadas ao Login do usuário. Teremos 2 métodos, Login e ChangePassword.

- Login
    
    Verificaremos se o os dados necessários para fazer login foi enviar no body. Caso não tenha, iremos enviar um erro de Bad Request - já que está faltando dados.
    
    ```tsx
    class AuthController {
      static login = async (req: Request, res: Response) => {
        //Verificar se a senha e username foi enviado
        let { username, password } = req.body;
        if (!(username && password)) {
          res.status(400).send();
        }
    }
    ```
    
    ---
    
    Então iremos pegar o repositório do User, iremos declarar um novo usuário e tentaremos de forma assíncrona buscar o username enviado no body. Trataremos caso ocorra algum erro, e enviaremos erro 401 indicando Não Autorizado.
    
    ```tsx
    //Pegar usuário do Banco de Dados.
        const userRepository = getRepository(User);
        let user: User;
        try {
          user = await userRepository.findOneOrFail({ where: { username } });
        } catch (error) {
          res.status(401).send();
        }
    }
    ```
    
    ---
    
    Após ter validado o usuário, então iremos verificar a senha. Caso a senha não esteja correta, iremos enviar um código 401. 
    
    Com a senha seja válida, podemos  criar um novo token e enviar ele.
    
    ```tsx
    //Vericar se a senha é válida.
        if (!user.checkIfUnencryptedPasswordIsValid(password)) {
          res.status(401).send();
          return;
        }
    
        //Criar novo jwt token
        const token = jwt.sign(
          { userId: user.id, username: user.username },
          config.jwtSecret,
          { expiresIn: "1h" }
        );
    
        //Enviamos token no Response
        res.send(token);
      };
    ```
    
- changePassword
    
    Iremos pegar o Id do usuário que quer trocar a senha de nosso Payload, iremos pegar também a senha atual e a nova senha e verificar se elas foram enviadas com exito no body.
    
    Após isso tentaremos buscar um novo usuário com a Id especifica. Caso o usuário for encontrado, usaremos o método o método que verifica se nossa senha está correta, do object User encontrado.
    
    ```tsx
    static changePassword = async (req: Request, res: Response) => {
        //Pegar is do Token
        const id = res.locals.jwtPayload.userId;
    
        //Pegar parâmetros enviados no Boyd
        const { oldPassword, newPassword } = req.body;
        if (!(oldPassword && newPassword)) {
          res.status(400).send();
        }
    
        //Pegar usuário do Database
        const userRepository = getRepository(User);
        let user: User;
        try {
          user = await userRepository.findOneOrFail(id);
        } catch (id) {
          res.status(401).send();
        }
    
        //Veririca se a senha antiga está correta
        if (!user.checkIfUnencryptedPasswordIsValid(oldPassword)) {
          res.status(401).send();
          return;
        }
    }
    ```
    
    ---
    
    A senha antiga estando correta, podemos assinar a nova senha no nosso usuário, e verificar se esse usuário continua sendo válido.
    
    Então iremos usar o método de hashPassword e salver o usuário.
    
    Após tudo ocorrer com sucesso, só nos resta enviar um código adequado 204, que indica que o resquest foi válido e o usuário não precisa sair dessa página.
    
    ```tsx
    //Validate de model (password lenght)
        user.password = newPassword;
        const errors = await validate(user);
        if (errors.length > 0) {
          res.status(400).send(errors);
          return;
        }
        //Hash the new password and save
        user.hashPassword();
        userRepository.save(user);
    
        res.status(204).send();
      };
    }
    export default AuthController;
    ```
    

****************************UserController****************************

Controller responsável por Buscar, Salver, Editar e Remover usuários. 

- listAll
    
    Iremos pegar o repository e tentar usar a função find, no qual iremos selecionar apenas os campos id, username e role para ser enviado.
    
    O método find retorna todos os usuário, sendo assim iremos enviar ele em nosso response.
    
    ```tsx
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
    }
    ```
    

---

- getOneById
    
    Iremo pegar a ID enviada pela URL
    
    Iremo epgar o Repositry e usar o método findOneOrFail, passando o id do usuário. Como no método anterior, não queremos mais campos além do id, username e role.
    
    ```tsx
    static getOneById = async (req: Request, res: Response) => {
        // Pegar o ID da url 
        const id: number = req.params.id;
    
        //Pegar o Banco de dados do usuário
        const userRepository = getRepository(User);
        try {
          const user = await userRepository.findOneOrFail(id, {
            select: ["id", "username", "role"]
          });
        } catch (error) {
          res.status(404).send("User not found");
        }
    		res.send(user);
      }
    }
    ```
    

---

- newUser
    
    Pegaremos os dados enviados no body, criaremos um novo usuário e assinaremos os campos username, passowrd e role que foi enviado para se criar um novo usuário.
    
    Após isso iremos verificase se o usuário criado está correto, usando uma função do ******************************class-validator****************************** que importamos, essa funçaõ validate, verifica se o usuário é um usuário válido, se todoso os campos estão corretos.
    
    Também iremos dar chamar o método hashPassword para incriptografar nossa senha.
    
    ```tsx
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
    }
    ```
    
    ---
    
    Após isso, tentaremos salvar nosso usuário no banco tratando caso ocorra algum erro. Se tudo der certo, enviaremos um status 201, dizendo que o usuário foi criado com sucesso.
    
    ```tsx
    const userRepository = getRepository(User);
        try {
          await userRepository.save(user);
        } catch (e) {
          res.status(409).send("username already in use");
          return;
        }
    
        res.status(201).send("User created");
      };
    ```
    
    ---
    
- editUser
    
    Pegaremos a ID do usuário que queremos editar e os parametros do body.
    
    Tentaremos buscar essa ID, caso o usuário seja encontrado, então iremos assinar o novo username e role do usuário, e usaremos o método validate para validar se continua sendo um usuário válido
    
    ```tsx
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
    }
    ```
    
    ---
    
    Após isso, iremos tentar salver o usuário. Caso ocorra algum erro, é porque o username já existe.
    
    Então enviamos um status code, 204 dizendo que os dados foi aceito, porém não a nada para responder.
    
    ```tsx
    // Tentado salvar, se falhar, significa que username está em uso 
        try {
          await userRepository.save(user);
        } catch (e) {
          res.status(409).send("username already in use");
          return;
        }
    
        // Depois, enviaremos um 204 (sem contexto, mas aceitado)
        res.status(204).send()
      }
    ```
    
    ---
    
- deleteUser
    
    Pegaremos a ID do usuário que quremos deletar, que foi enviada pela URL.
    
    após isso buscaremos esse usuário da mesma forma como estamos fazendo.
    
    Depois, basta user o chamar o método para deleta o usuário e enviar o código apropriada.
    
    ```tsx
    static delteteUser = async (req: Request, res: Response) => {
        // Pegar ID da url
        const id = req.params.id;
    
        const userRepository = getRepository(User);
        let user: User;
        try {
          user = await userRepository.findOneOrFail(id);
        } catch (error) {
          res.status(404).send("Usuário não encontrado")
          return;
        }
    
        res.status(204).send();
    
      }
    
    }
    
    export default UserController;
    ```
    
    ---
    
    ## IMPORTANTE
    
    - Essa aplicação não está completa, tentei estudar e fazer ela em pouco dias, o que acabou ocasionando em alguns erros no código.
    - Não só não está completa, como também não está atualizada, por isso desisti de estudar ela no meio do caminho.
    - Irei estudar e fazer outras aplicações mais atulizadas usando tecnologias com uma documentação melhor….
