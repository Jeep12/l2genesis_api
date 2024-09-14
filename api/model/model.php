    <?php
require_once(__DIR__ . '/../../config.php');

    use Firebase\JWT\JWT;
    use Firebase\JWT\Key;
    use Kreait\Firebase\Factory;
    use Kreait\Firebase\Auth as FirebaseAuth;

    class Model
    {

        protected $pdo;
        protected $firebaseAuth;
        protected $errorMessage; // Nueva variable para almacenar mensajes de error

        public function __construct()
        {
            $this->conectar();
            $this->initializeFirebaseAuth();
        }

        private function conectar()
        {
            global $parametros;
            $host = $parametros['host'];
            $db = $parametros['db'];
            $user = $parametros['user'];
            $password = $parametros['password'];

            $dsn = "mysql:host=$host;dbname=$db;charset=UTF8";

            try {
                $this->pdo = new PDO($dsn, $user, $password);
         
            } catch (PDOException $e) {
		   error_log("Database Connection Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database connection error: ' . $e->getMessage()]);
        exit();
            }
        }

        private function initializeFirebaseAuth()
        {
            global $parametros;

            try {
                $this->firebaseAuth = (new Factory)
                    ->withServiceAccount($parametros['firebase_service_account'])
                    ->createAuth();
            } catch (\Exception $e) {
                error_log("Firebase Initialization Error: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'Firebase initialization error: ' . $e->getMessage()]);
            }
        }


        // Método para obtener la clave secreta JWT
        protected function getJWTSecretKey()
        {
            global $parametros;
            return $parametros['jwt_secret_key'];
        }

   

        public function verifyGoogleToken($idToken)
        {
            try {
                $verifiedIdToken = $this->firebaseAuth->verifyIdToken($idToken);
                return $verifiedIdToken; // Debería devolver el objeto de token verificado
            } catch (\Exception $e) {
                error_log("Firebase Token Verification Error: " . $e->getMessage());
                return false;
            }
        }
        
        


        // Método para obtener el mensaje de error si el token no es válido
        public function getErrorMessage()
        {
            return $this->errorMessage;
        }
    }
