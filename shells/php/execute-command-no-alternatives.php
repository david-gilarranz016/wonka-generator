
////////////////////////////////////////////////////////////////////////////////////////////////
// Required classes and definitions for Command-Execution with no alternatives identification //
////////////////////////////////////////////////////////////////////////////////////////////////

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

class SetExecutionMethodStep implements Step
{
    private $executionMethod;

    public function __construct(ExecutionMethod $executionMethod)
    {
        $this->executionMethod = $executionMethod;
    }


    public function run(): void
    {
        // Configure the SystemService to use the selected ExecutionMethod
        SystemService::getInstance()->setExecutionMethod($this->executionMethod);
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// Required configuration for Command-Execution with no alternatives identification //
//////////////////////////////////////////////////////////////////////////////////////

$executionMethod = new ShellExecExecutionMethod();
array_push($steps, new SetExecutionMethodStep($executionMethod));

$actions['execute_command'] = new ExecuteCommandAction();

