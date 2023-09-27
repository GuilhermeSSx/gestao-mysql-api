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
                    'INSERT INTO usuarios (name, email, password) VALUES (?,?,?)',
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

    cadastrarComGoogle(request: Request, response: Response) {
        const { name, email, google_id, password } = request.body;

        // Verifique se já existe um usuário com o mesmo email ou google_id
        pool.getConnection((err: any, connection: any) => {
            if (err) {
                return response.status(500).json({ error: "Erro no servidor" });
            }

            connection.query(
                'SELECT * FROM usuarios WHERE email = ? OR google_id = ?',
                [email, google_id],
                (error: any, results: any) => {
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
                    hash(password, 10, (hashErr, hashedPassword) => {
                        if (hashErr) {
                            connection.release();
                            return response.status(500).json({ error: "Erro no servidor" });
                        }

                        connection.query(
                            'INSERT INTO usuarios (name, email, google_id, password) VALUES (?,?,?,?)',
                            [name, email, google_id, hashedPassword],
                            (insertError: any, result: any) => {
                                connection.release();

                                if (insertError) {
                                    return response.status(400).json({ error: "Erro ao cadastrar o usuário" });
                                }

                                response.status(200).json({ message: 'Usuário criado com sucesso!' });
                            }
                        );
                    });
                }
            );
        });
    }

    async linkGoogleAccount(request: Request, response: Response) {
        const { userId, googleId } = request.body;

        pool.getConnection((err: any, connection: any) => {
            if (err) {
                return response.status(500).json({ error: "Erro ao vincular a conta do Google" });
            }

            connection.query(
                'UPDATE usuarios SET google_id = ? WHERE id = ?',
                [googleId, userId],
                (error: any, result: any, fields: any) => {
                    connection.release();
                    if (error) {
                        return response.status(400).json({ error: "Erro ao vincular a conta do Google" });
                    }
                    response.status(200).json({ message: 'Conta do Google vinculada com sucesso!' });
                }
            );
        });
    }

    login(request: Request, response: Response) {
        const { email, password, googleId } = request.body; // Adicione o googleId à requisição

        pool.getConnection((err: any, connection: any) => {
            if (err) {
                return response.status(500).json({ error: "Erro na sua autenticação!" });
            }

            // Defina um tempo limite para a consulta SQL em milissegundos (por exemplo, 5000 para 5 segundos)
            connection.config.queryTimeout = 5000;

            connection.query(
                'SELECT * FROM usuarios WHERE email = ?',
                [email],
                (error: any, results: any, fields: any) => {
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

                    compare(password, results[0].password, (err, result) => {
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
                                google_id: resultado[0].google_id
                            }
                        });
                    }
                );
            });
        }
    }
}

export { UserRepository };
