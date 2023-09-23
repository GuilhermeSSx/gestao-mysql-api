import { pool } from '../../mysql';
import { hash, compare } from 'bcrypt';
import { sign, verify } from 'jsonwebtoken';
import { Request, Response } from 'express';


class UserRepository {
    cadastrar(request: Request, response: Response) {

        const { nome, email, password } = request.body;
        pool.getConnection((err: any, connection: any) => {
            hash(password, 10, (err, hash) => {
                if (err) {
                    return response.status(500).json(err);
                }

                connection.query(
                    'INSERT INTO usuarios ( nome, email, password) VALUES (?,?,?)',
                    [nome, email, hash],
                    (error: any, result: any, fileds: any) => {
                        connection.release();
                        if (error) {
                            return response.status(400).json(error);
                        }
                        response.status(200).json({ message: 'Usuario criado com sucesso!' });
                    }
                )
            })
        })

    }

    login(request: Request, response: Response) {
        const { email, password } = request.body;
        pool.getConnection((err: any, connection: any) => {
            connection.query(
                'SELECT * FROM usuarios WHERE email = ?',
                [email],
                (error: any, results: any, fileds: any) => {
                    connection.release();
                    if (error) {
                        return response.status(400).json({ error: "Erro na sua autenticação! " });
                    }

                    if (results.length === 0) {
                        // Usuário não encontrado, retorne uma resposta apropriada
                        return response.status(404).json({ error: "Usuário não encontrado" });
                    }

                    compare(password, results[0].password, (err, result) => {
                        if (err) {
                            return response.status(400).json({ error: "Erro na sua autenticação! " });
                        }

                        if (result) {
                            // jsonwebtoken JWT
                            const token = sign({
                                id_usuario: results[0].id_usuario,
                                email: results[0].email
                            }, process.env.SECRET as string, { expiresIn: "1d" });

                            const nome = results[0].nome; // Adicione esta linha para obter o nome do usuário

                            return response.status(200).json({ token: token, nome: nome, message: 'Autenticado com sucesso.' });
                        }
                    })
                }
            )
        })
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
                            })
                        }

                        console.log(resultado);

                        return response.status(201).send({
                            usuarios: {
                                nome: resultado[0].nome,
                                email: resultado[0].email,
                                id_usuario: resultado[0].id_usuario,
                            }
                        })
                    }
                )
            })
        }
    }


}

export { UserRepository };