<?php

require_once('model.php');
require_once('vendor/autoload.php');  // Incluye autoload.php de Composer para JWT y PHPMailer

use App\Mailer;

class ClientAccountModel  extends Model
{




    public function selectAccountByLogin($login)
    {
        $query = $this->pdo->prepare('SELECT * FROM accounts WHERE login = ?');
        $query->execute([$login]);
        $user = $query->fetch(PDO::FETCH_OBJ);
        return $user;
    }
    public function createAccountGame($login, $password, $email)
    {
        $sql = "INSERT INTO accounts ( login, password, email) VALUES (?, ?, ?)";

        $query = $this->pdo->prepare($sql);
        $query->execute([$login, $password, $email]);
        $result = $this->pdo->lastInsertId();
        return $result;
    }
}
