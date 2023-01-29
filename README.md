# Readme

# Aprendendo a fazer uma completa aplicação usando REST API, com autenticação JWT e autorização, usando o poder de TypeScript.

## Vamos começar !

Vamos começar usando a ferramenta de CLI do TypeORM, que nos permite criar uma aplicação base para começarmos. Então precisamos instalar TypeORM  e então configurar nossa aplicação.

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

[https://camo.githubusercontent.com/5bbdccae8d2b4ab7a2d003d9e9f5b75c98818ae830d26160294db77d10273af8/68747470733a2f2f63646e2d696d616765732d312e6d656469756d2e636f6d2f6d61782f323030302f312a63745a3775504e457438586d6b6e6a62324f483865412e706e67](https://camo.githubusercontent.com/5bbdccae8d2b4ab7a2d003d9e9f5b75c98818ae830d26160294db77d10273af8/68747470733a2f2f63646e2d696d616765732d312e6d656469756d2e636f6d2f6d61782f323030302f312a63745a3775504e457438586d6b6e6a62324f483865412e706e67)

### Index.ts

Iremos criar um nova conexão conexão com o banco de dados, então iremos inicializar nossa aplicação express. É importante também chamar os middlewares que usares (cors, bodyparser e helmet), setar a pasta onde estará nossas rotas e ouvir a porta em que nossa aplicação estará: 3000

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

Além dos middlewares que importamos, iremos precisar criar outros que nós ajudará a trabalhar com o JWT. Iremos criar nosso middlewares dentro das pasta de middlewares.

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
    
    Assinamos então nosso Payload com o retorno da função jwt.verify, passando nosso token e nossa chave secreta como parâmetros. Esse payload contém os dados do usuário, iremos usar o locals de nosso response para enviar esse payload. Caso ocorra algum erro, iremos enviar o código 401 (não autorizado) e pararemos nosso token por aí.
    
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
