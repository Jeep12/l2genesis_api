<?php

require_once("libs/Router.php");
require_once("api/controller/AuthController.php");
require_once("api/controller/ClientAccountController.php");

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE");
header("Access-Control-Allow-Headers: Origin, Content-Type, Accept, Authorization, X-Custom-Header");

// Manejo de solicitudes OPTIONS (preflight request)
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit;
}

// Crear una instancia del Router
$router = new Router();

//RUTAS AUTH
$router->addRoute('register', 'POST', 'AuthController', 'registerAccount');
$router->addRoute('login', 'POST', 'AuthController', 'login');
$router->addRoute('verifyToken', 'POST', 'AuthController', 'validateToken');
$router->addRoute('verifyEmail', 'GET', 'AuthController', 'verifymail');
$router->addRoute('loginWithGoogle', 'GET', 'AuthController', 'loginGoogle');
$router->addRoute('resend_verification', 'POST', 'AuthController', 'resendEmailVerification');


//RUTAS CLIENT GAME
$router->addRoute('registerAccountGame', 'POST', 'ClientAccountController', 'createAccountGame');

$router->addRoute('pruebaHost', 'POST', 'ClientAccountController', 'metodoPrueba');


// Extraer el recurso y el verbo
$url = $_GET['resource'] ?? '';
$verb = $_SERVER['REQUEST_METHOD'];



// Enrutar la solicitud
$router->route($url, $verb);
