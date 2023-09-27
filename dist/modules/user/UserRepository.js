"use strict";
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
                connection.query('INSERT INTO usuarios (nome, email, password) VALUES (?,?,?)', [name, email, hash], (error, result, fileds) => {
                    connection.release();
                    if (error) {
                        return response.status(400).json(error);
                    }
                    response.status(200).json({ message: 'Usuário criado com sucesso!' });
                });
            });
        });
    }
    login(request, response) {
        const { email, password } = request.body;
        mysql_1.pool.getConnection((err, connection) => {
            if (err) {
                return response.status(500).json({ error: "Erro na sua autenticação!" });
            }
            // Defina um tempo limite para a consulta SQL em milissegundos (por exemplo, 5000 para 5 segundos)
            connection.config.queryTimeout = 5000;
            connection.query('SELECT * FROM usuarios WHERE email = ?', [email], (error, results, fileds) => {
                connection.release();
                if (error) {
                    return response.status(400).json({ error: "Erro na sua autenticação!" });
                }
                if (results.length === 0) {
                    // Usuário não encontrado, retorne uma resposta apropriada
                    return response.status(404).json({ error: "Usuário não encontrado" });
                }
                (0, bcrypt_1.compare)(password, results[0].password, (err, result) => {
                    if (err) {
                        return response.status(400).json({ error: "Erro na sua autenticação!" });
                    }
                    if (result) {
                        // Não inclua o token na resposta
                        const name = results[0].name; // Adicione esta linha para obter o nome do usuário
                        const id = results[0].id;
                        const email = results[0].email;
                        return response.status(200).json({ id, name, email, message: 'Autenticado com sucesso.' });
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
                        }
                    });
                });
            });
        }
    }
}
exports.UserRepository = UserRepository;
//# sourceMappingURL=UserRepository.js.map