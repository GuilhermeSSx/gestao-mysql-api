"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRepository = void 0;
const mysql_1 = require("../../mysql");
const bcrypt_1 = require("bcrypt");
const jsonwebtoken_1 = require("jsonwebtoken");
class UserRepository {
    cadastrar(request, response) {
        const { name, email, password } = request.body;
        mysql_1.pool.getConnection((err, connection) => {
            (0, bcrypt_1.hash)(password, 10, (err, hash) => {
                if (err) {
                    return response.status(500).json(err);
                }
                connection.query('INSERT INTO usuarios (name, email, password) VALUES (?,?,?)', [name, email, hash], (error, result, fileds) => {
                    connection.release();
                    if (error) {
                        return response.status(400).json(error);
                    }
                    response.status(200).json({ message: 'Usuário criado com sucesso!' });
                });
            });
        });
    }
    verifyUserByEmailOrGoogleId(request, response) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                const { email, googleId } = request.query;
                mysql_1.pool.getConnection((error, connection) => {
                    if (error) {
                        reject(error);
                        return;
                    }
                    // Consulta SQL para verificar a existência do usuário com base no email ou google_id
                    const query = 'SELECT * FROM usuarios WHERE email = ? OR google_id = ?';
                    connection.query(query, [email, googleId], (queryError, results) => {
                        connection.release();
                        if (queryError) {
                            reject(queryError);
                            return;
                        }
                        // Se houver resultados, significa que o usuário existe
                        if (results.length > 0) {
                            resolve(true);
                        }
                        else {
                            resolve(false);
                        }
                    });
                });
            });
        });
    }
    cadastrarComGoogle(request, response) {
        const { name, email, google_id, password } = request.body;
        // Verifique se já existe um usuário com o mesmo email ou google_id
        mysql_1.pool.getConnection((err, connection) => {
            if (err) {
                return response.status(500).json({ error: "Erro no servidor" });
            }
            connection.query('SELECT * FROM usuarios WHERE email = ? OR google_id = ?', [email, google_id], (error, results) => {
                if (error) {
                    connection.release();
                    return response.status(500).json({ error: "Erro na verificação de usuário existente" });
                }
                // Se um usuário com o mesmo email ou google_id já existe, retorne um erro
                if (results.length > 0) {
                    connection.release();
                    return response.status(400).json({ error: "Usuário com o mesmo email ou google_id já existe" });
                }
                // Se não houver usuário existente, insira o novo usuário no banco de dados
                (0, bcrypt_1.hash)(password, 10, (hashErr, hashedPassword) => {
                    if (hashErr) {
                        connection.release();
                        return response.status(500).json({ error: "Erro no servidor" });
                    }
                    connection.query('INSERT INTO usuarios (name, email, google_id, password) VALUES (?,?,?,?)', [name, email, google_id, hashedPassword], (insertError, result) => {
                        connection.release();
                        if (insertError) {
                            return response.status(400).json({ error: "Erro ao cadastrar o usuário" });
                        }
                        response.status(200).json({ message: 'Usuário criado com sucesso!' });
                    });
                });
            });
        });
    }
    linkGoogleAccount(request, response) {
        return __awaiter(this, void 0, void 0, function* () {
            const { userId, googleId } = request.body;
            mysql_1.pool.getConnection((err, connection) => {
                if (err) {
                    return response.status(500).json({ error: "Erro ao vincular a conta do Google" });
                }
                connection.query('UPDATE usuarios SET google_id = ? WHERE id = ?', [googleId, userId], (error, result, fields) => {
                    connection.release();
                    if (error) {
                        return response.status(400).json({ error: "Erro ao vincular a conta do Google" });
                    }
                    response.status(200).json({ message: 'Conta do Google vinculada com sucesso!' });
                });
            });
        });
    }
    login(request, response) {
        const { email, password, googleId } = request.body; // Adicione o googleId à requisição
        mysql_1.pool.getConnection((err, connection) => {
            if (err) {
                return response.status(500).json({ error: "Erro na sua autenticação!" });
            }
            // Defina um tempo limite para a consulta SQL em milissegundos (por exemplo, 5000 para 5 segundos)
            connection.config.queryTimeout = 5000;
            connection.query('SELECT * FROM usuarios WHERE email = ?', [email], (error, results, fields) => {
                connection.release();
                if (error) {
                    return response.status(400).json({ error: "Erro na sua autenticação!" });
                }
                if (results.length === 0) {
                    // Usuário não encontrado, retorne uma resposta apropriada
                    return response.status(404).json({ error: "Usuário não encontrado" });
                }
                if (googleId && !results[0].google_id) {
                    // Se o usuário está fazendo login com o Google, mas a conta do Google não está vinculada
                    return response.status(401).json({ error: "A conta do Google não está vinculada. Faça a vinculação." });
                }
                (0, bcrypt_1.compare)(password, results[0].password, (err, result) => {
                    if (err) {
                        return response.status(400).json({ error: "Erro na sua autenticação!" });
                    }
                    if (result || results[0].google_id) {
                        // Se a senha está correta ou a conta do Google já está vinculada
                        const id = results[0].id;
                        const name = results[0].name;
                        const userEmail = results[0].email;
                        const userGoogleId = results[0].google_id; // Inclua o google_id na resposta, se existir
                        return response.status(200).json({ id, name, email: userEmail, google_id: userGoogleId, message: 'Autenticado com sucesso.' });
                    }
                    else {
                        // Senha incorreta
                        return response.status(401).json({ error: "Senha incorreta" });
                    }
                });
            });
        });
    }
    getUser(request, response) {
        const decode = (0, jsonwebtoken_1.verify)(request.headers.authorization, process.env.SECRET);
        if (decode.email) {
            mysql_1.pool.getConnection((error, conn) => {
                conn.query('SELECT * FROM usuarios WHERE email = ?', [decode.email], (error, resultado, fileds) => {
                    conn.release();
                    if (error) {
                        return response.status(400).send({
                            error: error,
                            response: null
                        });
                    }
                    console.log(resultado);
                    return response.status(201).send({
                        usuarios: {
                            name: resultado[0].name,
                            email: resultado[0].email,
                            id: resultado[0].id,
                            google_id: resultado[0].google_id
                        }
                    });
                });
            });
        }
    }
}
exports.UserRepository = UserRepository;
//# sourceMappingURL=UserRepository.js.map