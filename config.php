<?php


require 'vendor/autoload.php';

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$parametros = [
    'host' => $_ENV['DB_HOST'],
    'db' => $_ENV['DB_NAME'],
    'user' => $_ENV['DB_USER'],
    'password' => $_ENV['DB_PASSWORD'],
    'key_email' => $_ENV['EMAIL_KEY'],
    'sid' => $_ENV['TWILIO_SID'],
    'token' => $_ENV['TWILIO_TOKEN'],
    'jwt_secret_key' => $_ENV['JWT_SECRET_KEY'],
    'firebase_service_account' => $_ENV['FIREBASE_SERVICE_ACCOUNT']
];


?>
