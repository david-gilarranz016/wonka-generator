
/////////////////////////////////////////////////////////////
// Required classes and configuration to add IP Validation //
/////////////////////////////////////////////////////////////

class AddIPValidatorStep implements Step
{
    private $whitelist;

    public function __construct($whitelist)
    {
        $this->whitelist = $whitelist;
    }

    public function run()
    {
        // Create a new IP validator with the supplied whitelist
        $ipValidator = new IPValidator($this->whitelist);

        // Add the validator to the SecurityService
        SecurityService::getInstance()->addValidator($ipValidator);
    }
}

class IPValidator implements Validator
{
    private $ipWhiteList = [];

    public function __construct($ipWhiteList)
    {
        // Initialize the whitelist
        $this->ipWhiteList = $ipWhiteList;
    }

    public function validate($request)
    {
        // Return true if the source address of the request is in the whitelist
        return in_array($request->getSource(), $this->ipWhiteList, true);
    }
}

// Setup IP validation
array_push($steps, new AddIPValidatorStep([IP_WHITELIST]));

