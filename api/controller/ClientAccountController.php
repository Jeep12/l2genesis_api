<?php

require_once "api/view/api-view.php";
require_once "api/utils/JwtMiddleware.php";
require_once "api/model/ClientAccountModel.php";

use Api\Utils\JwtMiddleware;

class ClientAccountController
{
    private $cacheDir;
    private $view;
    private $JWTMiddleware;
    private $data;
    private $clientModel;

    public function __construct()
    {
        $this->cacheDir = CACHE_DIR;
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0777, true);
        }
        $this->view = new APIView();
        $this->clientModel = new ClientAccountModel();
        $this->JWTMiddleware = new JwtMiddleware();
        $this->data = file_get_contents("php://input");
    }

    private function get_data()
    {
        return json_decode($this->data);
    }

    public function createAccountGame()
    {
        $customHeader = $_SERVER['HTTP_X_CUSTOM_HEADER'] ?? null;
        $jwt = $customHeader ? str_replace('Bearer ', '', $customHeader) : null;

        if ($jwt && $this->JWTMiddleware->validateJWT($jwt)) {
            $data = $this->get_data();

            if (!empty($data)) {
                $login = $data->login ?? null; // Asegúrate de que 'login' no sea null
                $email = $data->email ?? null;
                $password = $data->password ?? null;

                if ($login && $email && $password) {
                    $account = $this->clientModel->selectAccountByLogin($login);

                    if (!$account) {
                        $passwordBase = base64_encode(pack('H*', sha1($password)));
                        $createAccount = $this->clientModel->createAccountGame($login, $passwordBase, $email);
                        $this->view->response(['message' => 'Cuenta creada con éxito', 'id' => $createAccount], 201);
                    } else {
                        $this->view->response(['message' => 'Esta cuenta ya existe'], 409);
                    }
                } else {
                    $this->view->response(['message' => 'Datos del formulario vacíos o inválidos'], 400);
                }
            } else {
                $this->view->response(['message' => 'Error en los datos'], 400);
            }
        } else {
            $this->view->response(['message' => 'Token inválido'], 401);
        }
    }
}
