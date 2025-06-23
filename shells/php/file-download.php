
//////////////////////////////////////////////////////////////////
// Required classes and configuration for File-Download support //
//////////////////////////////////////////////////////////////////

class DownloadFileAction implements Action
{
    public function run($args)
    {
        // Check the required mode (binary or text)
        $mode = ($args->binary) ? 'rb' : 'r';

        // Open and read the requested file
        $path = SystemService::getInstance()->getCurrentDir() . '/' . $args->filename;
        $fd = fopen($path, $mode);
        $content = fread($fd, filesize($path));
        fclose($fd);

        // Return the base64 encoded contents of the file
        return base64_encode($content);
    }
}

// Add a DownloadFileAction to the Action array
$actions['download_file'] = new DownloadFileAction();

