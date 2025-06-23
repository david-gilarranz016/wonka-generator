
///////////////////////////////////////////////////////////////////////
// Required classes and comfiguration to implement Replay Protection //
///////////////////////////////////////////////////////////////////////

class AddNonceValidatorStep implements Step
{
    private $nonce;

    public function __construct($nonce)
    {
        $this->nonce = $nonce;
    }

    public function run()
    {
        // Add a nonce validator to the SecurityService  
        $nonceValidator = new NonceValidator;
        SecurityService::getInstance()->addValidator($nonceValidator);

        // If not initialized, set the initial nonce value
        if (!isset($_SESSION['nonce'])) {
            SecurityService::getInstance()->setNonce($this->nonce);
        }
    }
}

class NonceValidator implements Validator
{
    public function validate($request)
    {
        // Check that nonce is the one stored in the SecurityService
        $securityService = SecurityService::getInstance();
        $valid = $request->getNonce() == $securityService->getNonce();

        // If the nonce is valid, update the SecurityService to generate a new Nonce
        if ($valid) {
            $nonce = bin2hex(random_bytes(16));
            $securityService->setNonce($nonce);
        }

        // Return the validation result
        return $valid;
    }
}

// Add NonceValidation to the bootstrapping process
array_push($steps, new AddNonceValidatorStep('NONCE'));

