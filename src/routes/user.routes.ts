import { Router } from "express";
import { UserRepository } from "../modules/user/UserRepository";

const userRoutes = Router();
const userRepository = new UserRepository();

// rotas
userRoutes.post('/sign-up', (request, response) => {
    userRepository.cadastrar(request, response);
})

userRoutes.post('/sign-in', (request, response) => {
    userRepository.login(request, response);
})

userRoutes.post('/link-google', (request, response) => {
    userRepository.linkGoogleAccount(request, response);
})

userRoutes.get('/get-user', (request, response) => {
    userRepository.getUser(request, response);
})


export { userRoutes };