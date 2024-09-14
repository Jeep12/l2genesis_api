<?php
namespace App;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Mailer {
    private $mail;

    public function __construct() {
        $this->mail = new PHPMailer(true);

        // Configuración SMTP
        $this->mail->isSMTP();
        $this->mail->Host = 'smtp.gmail.com';
        $this->mail->SMTPAuth = true;
        $this->mail->Username = 'l2.genesis.online@gmail.com'; // Tu correo de Gmail
        $this->mail->Password = $this->getSecretKeyEmail(); // Contraseña o clave de aplicación
        $this->mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // Usar TLS para puerto 587
        $this->mail->Port = 587;

        // Configuración del remitente
        $this->mail->setFrom('l2.genesis.online@gmail.com', 'GENESIS L2'); // Debe ser el mismo que Username

        // Habilitar depuración para ver errores detallados
    }

private function getSecretKeyEmail()
{
    global $parametros;
    // Asegúrate de que esta clave sea correcta, y no tenga guiones ni otros caracteres especiales si es necesario
    return str_replace('-', ' ', $parametros['key_email']); // Reemplaza '-' por espacio si es necesario
}
    public function sendMail($to, $subject, $body) {
        try {
            $this->mail->addAddress($to);
            $this->mail->Subject = $subject;
            $this->mail->isHTML(true); // Asegura que el correo se envíe como HTML

            $this->mail->Body = $body;
            $this->mail->send();
            return "Correo enviado correctamente";
        } catch (Exception $e) {
            return "El correo no pudo ser enviado. Error: {$this->mail->ErrorInfo}";
        }
    }
}
