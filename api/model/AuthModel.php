<?php

require_once('model.php');
require_once('vendor/autoload.php');  // Incluye autoload.php de Composer para JWT y PHPMailer

use App\Mailer;

class AuthModel extends Model
{

    public function getUserByEmail($email)
    {
        $query = $this->pdo->prepare('SELECT * FROM accounts_master WHERE email = ?');
        $query->execute([$email]);

        $user = $query->fetch(PDO::FETCH_OBJ);
        return $user;
    }

    public function createUser( $nombre, $apellido, $email, $password)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['message' => 'Correo electrónico inválido'];
        }

        $passwordHashing = password_hash($password, PASSWORD_ARGON2ID);

        $jwtMiddleware = new \Api\Utils\JwtMiddleware();
        $verificationToken = $jwtMiddleware->generateJWTVerification($email);

        $mailer = new Mailer();

        $query = $this->pdo->prepare('INSERT INTO accounts_master ( nombre, apellido, email, password, code_verification) VALUES (?, ?, ?, ?, ?)');
        $query->execute([ $nombre, $apellido, $email, $passwordHashing, $verificationToken]);

        $userId = $this->pdo->lastInsertId();
        $verificationLink = $this->generateVerificationLink($verificationToken);
        $emailContent = $this->getVerificationEmailContent($email, $verificationLink, $nombre, $apellido);

        $mailResult = $mailer->sendMail(
            $email,
            'Verifica tu correo',
            $emailContent
        );

        return [
            'id' => $userId,
            'message' => $mailResult
        ];
    }



    public function getIDbyEmail($email)
    {
        $sql = "SELECT id, nombre, apellido, email, emailVerified, code_verification FROM accounts_master WHERE email = ?";
        
        $query = $this->pdo->prepare($sql);
        $query->execute([$email]);
    
        $user = $query->fetch(PDO::FETCH_OBJ);
        return $user;
    }
    

    public function verifyUserByToken($token)
    {
        $jwtMiddleware = new \Api\Utils\JwtMiddleware();
        $decoded = $jwtMiddleware->validateJWT($token);
    
        if ($decoded) {
            $email = $decoded->email;
            if (!empty($email)) {
                $user = $this->getIDbyEmail($email);
    
                // Verifica si el usuario fue encontrado
                if ($user) {
                    $id = $user->id;
    
                    // Corrige la consulta de actualización
                    $query = $this->pdo->prepare('UPDATE accounts_master SET emailVerified = 1, code_verification = NULL WHERE id = ?');
                    $query->execute([$id]);
    
                    return true;
                } else {
                    // Usuario no encontrado
                    return false;
                }
            }
        } else {
            echo "Failed to decode token: " . $jwtMiddleware->getErrorMessage() . "\n";
        }
    
        return false;
    }
    


    public function getUserById($id)
    {
        try {
            // Preparar la consulta SQL
            $query = $this->pdo->prepare('SELECT nombre, admin, apellido, emailVerified FROM accounts_master WHERE id = :id');

            // Ejecutar la consulta con el parámetro proporcionado
            $query->execute(['id' => $id]);

            // Obtener el resultado como un objeto
            $user = $query->fetch(PDO::FETCH_OBJ);

            // Retornar el resultado si se encuentra el usuario, de lo contrario retorna null
            return $user ?: null;
        } catch (PDOException $e) {
            // Manejar cualquier error de base de datos
            error_log("Database Error: " . $e->getMessage());
            return null;
        }
    }



    public function createUserWithGoogle($nombre, $apellido, $email)
    {
        // Verifica si el correo electrónico es válido
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['message' => 'Correo electrónico inválido'];
        }

        // La contraseña no se usa en este caso, se establece en vacío
        $password = '';

        // La verificación de correo electrónico se establece en 1 ya que el usuario se ha autenticado con Google
        $emailVerified = 1;

        // Prepara la consulta para insertar el nuevo usuario
        $query = $this->pdo->prepare('INSERT INTO accounts_master (nombre, apellido, email, password, emailVerified) VALUES (?, ?, ?, ?, ?)');
        $query->execute([$nombre, $apellido, $email, $password, $emailVerified]);

        // Devuelve el ID del usuario recién creado y un mensaje de éxito
        $userId = $this->pdo->lastInsertId();

        return [
            'id' => $userId,
            'message' => 'Usuario creado con éxito'
        ];
    }

    public function updateUserWithGoogle($email, $emailVerified, $code)
    {
        // Valida el correo electrónico
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['message' => 'Correo electrónico inválido'];
        }

        // Verifica si el usuario ya existe
        $query = $this->pdo->prepare('SELECT * FROM accounts_master WHERE email = ?');
        $query->execute([$email]);
        $user = $query->fetch(PDO::FETCH_OBJ);

        if ($user) {
            // Si el usuario ya existe, actualízalo
            $query = $this->pdo->prepare('
                UPDATE accounts_master 
                SET emailVerified = ?, code_verification = ?
                WHERE email = ?
            ');
            $query->execute([$emailVerified, $code, $email]);

            return ['message' => 'Usuario actualizado con éxito.'];
        } else {
            // Si el usuario no existe, puedes optar por crear uno nuevo o manejarlo de otra manera
            return ['message' => 'Usuario no encontrado.'];
        }
    }



    public function updateUserVerificationToken($userId, $newToken)
    {
        $query = $this->pdo->prepare('UPDATE accounts_master SET code_verification = ? WHERE id = ?');
        $query->execute([$newToken, $userId]);
    }

    public function sendVerificationEmail($email, $verificationToken, $nombre, $apellido)
    {
        $mailer = new Mailer(); // Asegúrate de tener el autoload de Composer configurado para Mailer

        $verificationLink = $this->generateVerificationLink($verificationToken);
        $emailContent = $this->getVerificationEmailContent($email, $verificationLink, $nombre, $apellido);

        $mailResult = $mailer->sendMail(
            $email,
            'L2 Genesis - Verifica tu identidad',
            $emailContent
        );

        return $mailResult;
    }


    private function generateVerificationLink($token)
    {

        return "https://localhost/l2genesis_api/api/verifyEmail?token=$token";
    }

    private function getVerificationEmailContent($email, $verificationLink, $nombre, $apellido)
    {
        // Escapamos variables para evitar problemas de seguridad y formato
        $nombre = htmlspecialchars($nombre, ENT_QUOTES, 'UTF-8');
        $apellido = htmlspecialchars($apellido, ENT_QUOTES, 'UTF-8');
        $verificationLink = htmlspecialchars($verificationLink, ENT_QUOTES, 'UTF-8');

        // Contenido del email en HTML usando tablas para mayor compatibilidad
        return '
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    padding: 20px;
                    margin: 0;
                }
                .container {
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0px 0px 10px 0px rgba(0, 0, 0, 0.1);
                    max-width: 600px;
                    margin: 0 auto;
                }
                .header {
                    color: #333333;
                    font-size: 24px;
                    margin-bottom: 10px;
                    text-align: center;
                }
                .content {
                    color: #555555;
                    width: 80%;
                    padding: 10px;
                    margin: 0 auto;
                    text-align: center;
                }
                .footer {
                    margin-top: 20px;
                    font-size: 12px;
                    color: #aaaaaa;
                    text-align: center;
                }
                .btn {
                    background-color: rgba(66, 66, 66, 1);
                    color: white !important;
                    font-size: 20px;
                    font-weight: 700;
                    padding: 10px;
                    border-radius: 5px;
                    text-align: center;
                    text-decoration: none;
                    display: inline-block;
                    width: 200px;
                    margin: 10px auto;
                }
            </style>
        </head>
        <body>
            <table class="container" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                    <td class="header">¡Hola, ' . $nombre . ' ' . $apellido . '!</td>
                </tr>
                <tr>
                    <td class="content">
                        <p>Gracias por registrarse en L2 Genesis. Antes de empezar, necesitamos confirmar que eres tú. Por favor, confirma tu dirección de correo haciendo clic en el botón de abajo.</p>
                        <p>Este email es válido por 15 minutos.</p>
                        <br><br>
                        <a href="' . $verificationLink . '" class="btn">Verificar mi correo</a>
                        <br><br>
                        O copia y pega este enlace en tu navegador:<br>
                        <a href="' . $verificationLink . '">' . $verificationLink . '</a>
                    </td>
                </tr>
                <tr>
                    <td class="content">
                        <p>Si no solicitaste este correo, simplemente ignóralo.</p>
                    </td>
                </tr>
                <tr>
                    <td class="footer">
                        &copy; 2024 Lineage II Genesis. Todos los derechos reservados.
                    </td>
                </tr>
            </table>
        </body>
        </html>';
    }
}
