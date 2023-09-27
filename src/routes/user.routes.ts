import { Router } from "express";
import { UserRepository } from "../modules/user/UserRepository";

const userRoutes = Router();
const userRepository = new UserRepository();

// rotas
userRoutes.post('/sign-up', (request, response) => {
    userRepository.cadastrar(request, response);
})

userRoutes.post('/sign-up-google', (request, response) => {
    userRepository.cadastrarComGoogle(request, response);
})

userRoutes.post('/sign-in', (request, response) => {
    userRepository.login(request, response);
})

userRoutes.get('/get-user', (request, response) => {
    userRepository.getUser(request, response);
})

userRoutes.get('/verifica-email', (request, response) => {
    userRepository.verificaEmailExistente(request, response);
})


export { userRoutes };