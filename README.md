# Aprendendo a fazer uma completa aplicação usando REST API, com autenticação JWT e autorização, usando o poder de TypeScript.

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

*estrutura*

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
    
    more code