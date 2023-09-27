import { pool } from '../../mysql';
import { hash, compare } from 'bcrypt';
import { sign, verify } from 'jsonwebtoken';
import { Request, Response } from 'express';

class UserRepository {
    cadastrar(request: Request, response: Response) {
        const { name, email, password } = request.body;
        pool.getConnection((err: any, connection: any) => {
            hash(password, 10, (err, hash) => {
                if (err) {
                    return response.status(500).json(err);
                }

                connection.query(
                    'INSERT INTO usuarios (nome, email, password) VALUES (?,?,?)',
                    [name, email, hash],
                    (error: any, result: any, fileds: any) => {
                        connection.release();
                        if (error) {
                            return response.status(400).json(error);
                        }
                        response.status(200).json({ message: 'Usuário criado com sucesso!' });
                    }
                );
            });
        });
    }

    login(request: Request, response: Response) {
        const { email, password } = request.body;
        pool.getConnection((err: any, connection: any) => {
            if (err) {
                return response.status(500).json({ error: "Erro na sua autenticação!" });
            }

            // Defina um tempo limite para a consulta SQL em milissegundos (por exemplo, 5000 para 5 segundos)
            connection.config.queryTimeout = 5000;

            connection.query(
                'SELECT * FROM usuarios WHERE email = ?',
                [email],
                (error: any, results: any, fileds: any) => {
                    connection.release();
                    if (error) {
                        return response.status(400).json({ error: "Erro na sua autenticação!" });
                    }

                    if (results.length === 0) {
                        // Usuário não encontrado, retorne uma resposta apropriada
                        return response.status(404).json({ error: "Usuário não encontrado" });
                    }

                    compare(password, results[0].password, (err, result) => {
                        if (err) {
                            return response.status(400).json({ error: "Erro na sua autenticação!" });
                        }

                        if (result) {
                            // Não inclua o token na resposta
                            const name = results[0].name; // Adicione esta linha para obter o nome do usuário
                            const id = results[0].id;
                            const email = results[0].email;

                            return response.status(200).json({ id, name, email, message: 'Autenticado com sucesso.' });
                        } else {
                            // Senha incorreta
                            return response.status(401).json({ error: "Senha incorreta" });
                        }
                    });
                }
            );
        });
    }

    getUser(request: any, response: any) {
        const decode: any = verify(request.headers.authorization, process.env.SECRET as string);
        if (decode.email) {
            pool.getConnection((error, conn) => {
                conn.query(
                    'SELECT * FROM usuarios WHERE email = ?',
                    [decode.email],
                    (error, resultado, fileds) => {
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
                    }
                );
            });
        }
    }
}

export { UserRepository };
