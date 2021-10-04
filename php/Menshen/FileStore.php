<?php

namespace Menshen;

require('GenericUser.php');

class FILEStore implements CertStore {
    protected $path;
    function __construct ($path) {
      if (!is_dir($path) || !is_readable($path)) {
        throw new \Exception('Path is not a dir or readable "' . $path . '"');
      }
    }
    function init() { return true; }

    function beginCheck() { return true; }

    function endCheck($clientId, $success) { return true; }

    function getUser($clientId) {
      $fullpath = $this->path . '/' . $clientId . '.pem';
      $person = [
        'uid' => $clientId,
        'certificate' => null
      ];
      if (is_readable($fullpath)) {
        $pem = file_get_contents($fullpath);
        if ($pem) {
          $person['certificate'] = $pem;
        }
      }
      return new GenericUser($person);
    }
  }