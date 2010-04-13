<?

  function throwError($message)
  {
    header('Status: 500 Internal Server Error');
    die($message);
  }

  function processRequest()
  {
    if (!isset($_POST['input']))
      throwError('Not defined: "input".');
      
    $input = $_POST['input'];
    $titlecase = dirname(__FILE__) . '/titlecase.pl';
    $command = 'echo "' . escapeshellarg($input) . '" | ' . $titlecase;
    passthru($command);
  }
  
  processRequest();

?>