<?php
require_once "api/model/AuthModel.php";
require_once "api/view/api-view.php";
require_once "api/utils/JwtMiddleware.php";
define('CACHE_DIR', __DIR__ . '/cache/');
// Asegúrate de que la ruta sea correcta
use Api\Utils\JwtMiddleware;
use App\Mailer;

class AuthController
{

    private $cacheDir;
    private $view;
    private $JWTMiddleware; // Añade el middleware
    private $data;
    private $AuthModel;

    public function __construct()
    {
        $this->cacheDir = CACHE_DIR;
        // Verificar y crear el directorio de caché si no existe
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0777, true);
        }
        $this->AuthModel = new AuthModel();
        $this->view = new APIView();
        $this->JWTMiddleware = new JwtMiddleware(); // Inicializa el middleware

        $this->data = file_get_contents("php://input");
    }
    private function get_data()
    {
        return json_decode($this->data);
    }


    public function RegisterAccount()
    {
        $data = $this->get_data();
        if (!empty($data)) {

            $nombre = $data->nombre;
            $apellido = $data->apellido;
            $email = $data->email;
            $password = $data->password;

            $existingUser = $this->AuthModel->getUserByEmail($email);

            if ($existingUser) {
                $this->view->response(['error' => 'User already exists'], 409);
            } else {
                $result = $this->AuthModel->createUser($nombre, $apellido, $email, $password);

                if (isset($result['id'])) {
                    $this->view->response($result, 201);
                } else {
                    $this->view->response(['error' => 'Failed to create user'], 500);
                }
            }
        } else {
            $this->view->response("Error en los datos", 209);
        }
    }



    public function login()
    {
        // Obtener datos de la solicitud
        $data = $this->get_data();

        // Validar datos de entrada
        if (!isset($data->email) || !isset($data->password)) {
            $this->view->response("Email and password are required", 400);
            return;
        }

        $email = $data->email;
        $password = $data->password;

        // Verificar el formato del email
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->view->response("Invalid email format", 400);
            return;
        }

        // Obtener el usuario por email
        $user = $this->AuthModel->getUserByEmail($email);

        // Verificar si el usuario existe y la contraseña es correcta
        if ($user) {
            if (password_verify($password, $user->password)) {
                // Generar el JWT
                $jwt = $this->JWTMiddleware->generateJWT($user->email, $user->admin, $user->nombre, $user->apellido, $user->emailVerified);
                $this->view->response(['token' => $jwt], 200);
            } else {
                $this->view->response("Invalid credentials", 401);
            }
        } else {
            $this->view->response("User not found", 404);
        }
    }


    public function validateToken()
    {
        $customHeader = $_SERVER['HTTP_X_CUSTOM_HEADER'] ?? null;
        $jwt = $customHeader ? str_replace('Bearer ', '', $customHeader) : null;

        if ($jwt && $this->JWTMiddleware->validateJWT($jwt)) {
            $this->view->response(['valid' => true, 'message' => 'Token válido'], 200);
        } else {
            $this->view->response(['valid' => false, 'message' => 'Token inválido'], 401);
        }
    }



    public function verifymail()
    {
        // Verifica si el token está presente en la URL
        if (isset($_GET['token'])) {
            $token = $_GET['token'];

            // Llama al modelo para verificar el token

            $verified = $this->AuthModel->verifyUserByToken($token);

            if ($verified) {
                // Responde con un mensaje de éxito
                echo "<body style='background-color: #2c2c2c;display:flex;align-items:center;justify-content:center;'>";
                echo "<h1 style='text-align:center;text-transform:uppercase;color:white;font-family: Ubuntu Sans Mono, monospace;border:2px solid white;border-left:5px solid white;border-bottom:7px solid white;padding:20px;'>Correo verificado con exitó! ";

                echo "</body>";
            } else {
                // Responde con un mensaje de error si el token no es válido
                $this->view->response(['message' => 'Token de verificación inválido o ya utilizado.'], 400);
            }
        } else {
            // Responde con un mensaje de error si el token no está presente
            $this->view->response(['message' => 'Token de verificación no proporcionado.'], 400);
        }
    }



    public function loginGoogle()
    {
        $customHeader = isset($_SERVER['HTTP_X_CUSTOM_HEADER']) ? $_SERVER['HTTP_X_CUSTOM_HEADER'] : null;

        if ($customHeader) {
            $firebaseToken = str_replace('Bearer ', '', $customHeader);

            $decodedToken = $this->AuthModel->verifyGoogleToken($firebaseToken);

            if ($decodedToken && is_object($decodedToken)) {
                // Extrae la información del payload
                $claims = $decodedToken->claims();
                $email = $claims->get('email') ?? null;
                $displayName = $claims->get('name') ?? null;
                $expiryTime = $claims->get('exp') ?? null;

                // Convierte el tiempo de vencimiento a un formato legible
                $expiryDate = $expiryTime instanceof \DateTimeImmutable ? $expiryTime->format('Y-m-d H:i:s') : null;

                // Desarma el displayName en nombre y apellido
                list($nombre, $apellido) = explode(' ', $displayName, 2) + [NULL, NULL];

                $user = $this->AuthModel->getUserByEmail($email);

                if ($user) {
                    // Si el usuario ya existe, actualízalo
                    $this->AuthModel->updateUserWithGoogle(
                        $email,
                        1,
                        ''
                    );

                    $token = $this->JWTMiddleware->generateJWT($user->email, $user->admin, $user->nombre, $user->apellido, $user->emailVerified);
                    // Maneja el resultado de la actualización
                    $this->view->response([
                        'token' => $token,

                    ], 200);
                } else {
                    // Si el usuario no existe, créalo
                    $createResult = $this->AuthModel->createUserwithGoogle($nombre, $apellido, $email);

                    // Maneja el resultado de la creación
                    if (isset($createResult['id'])) {
                        $userById = $this->AuthModel->getUserById($createResult);

                        $rol = $userById->admin;
                        $token = $this->JWTMiddleware->generateJWT($user->email, $rol, $userById->nombre, $userById->apellido, $userById->emailVerified);

                        $this->view->response([

                            'token' => $token
                        ], 200);
                    } else {
                        $this->view->response([
                            'error' => 'Error al crear el usuario.',
                        ], 500);
                    }
                }
            } else {
                $this->view->response([
                    'error' => 'Token no válido'
                ], 401);
            }
        } else {
            $this->view->response([
                'error' => 'Token no proporcionado'
            ], 400);
        }
    }



    public function resendEmailVerification()
    {
        $customHeader = $_SERVER['HTTP_X_CUSTOM_HEADER'] ?? null;
        $jwt = $customHeader ? str_replace('Bearer ', '', $customHeader) : null;

        $data = $this->get_data();
        $email = $data->email ?? null;

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->view->response(['message' => 'Email is required or invalid'], 400);
            return;
        }

        // Validar el JWT
        $user = $this->AuthModel->getUserByEmail($email);
        if ($jwt && $this->JWTMiddleware->validateJWT($jwt)) {
            if (!$user) {
                $this->view->response(['message' => 'User not found'], 404);
                return;
            }


            // Verificar el tiempo desde el último envío
            $lastSentTimestamp = $this->getCache($email);
            $currentTimestamp = time();
            $interval = 15 * 60; // 15 minutos en segundos

            if ($lastSentTimestamp && ($currentTimestamp - $lastSentTimestamp) < $interval) {
                $remainingTime = $interval - ($currentTimestamp - $lastSentTimestamp);
                $this->view->response([
                    'message' => 'Please wait before requesting another verification email.',
                    'retry_after' => $remainingTime
                ], 429);
                return;
            }

            // Generar nuevo token de verificación
            $tokenVerification = $this->JWTMiddleware->generateJWTVerification($email,);
            $this->AuthModel->updateUserVerificationToken($user->id, $tokenVerification);

            // Enviar el correo de verificación
            $emailSent = $this->AuthModel->sendVerificationEmail($email, $tokenVerification,$user->nombre,$user->apellido);

            // Actualizar la caché con el nuevo timestamp
            $this->setCache($email, $currentTimestamp);

            // Responder éxito
            $this->view->response([
                'message' => 'Verification email sent successfully.',
                'email_sent' => $emailSent
            ], 200);
        } else {
            $this->view->response(['message' => 'Invalid or missing JWT'], 401);
        }
    }

    private function setCache($email, $timestamp)
    {
        $cacheFile = $this->cacheDir . md5($email) . '.cache';
        file_put_contents($cacheFile, $timestamp);
    }

    // Método para leer de caché
    private function getCache($email)
    {
        $cacheFile = $this->cacheDir . md5($email) . '.cache';
        if (file_exists($cacheFile)) {
            return file_get_contents($cacheFile);
        }
        return null;
    }

    // Método para eliminar la caché (opcional)
    private function clearCache($email)
    {
        $cacheFile = $this->cacheDir . md5($email) . '.cache';
        if (file_exists($cacheFile)) {
            unlink($cacheFile);
        }
    }

}
