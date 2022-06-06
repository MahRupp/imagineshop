import jwt from "jsonwebtoken";
import { UserService } from "../services/user-services.js";

export const authMiddleware = (req, res, next) => {
  const authorization = req.headers.authorization;
  const token = authorization ? authorization.split(" ")[1] : undefined;

  if (!token) {
    return res.status(401).json({ message: "Sem autorização. Faça o login" });
  }

  const secretKey = process.env.SECRET_KEY;
  jwt.verify(token, secretKey, { ignoreExpiration: false },
    async (err, decodedToken) => {
      if (err) {
        return res.status(401).json({message: 'Erro de autenticação'});
      }
      const isValidToken = decodedToken && decodedToken.user;
      if(!isValidToken){
        return res.status(401).json({message: 'Forbidden'});
      }
      
      const userService = new UserService();
      const user = await userService.findByEmail(decodedToken.user.email);
      if (user) {
        return next();
      }     
    }
  );
};
