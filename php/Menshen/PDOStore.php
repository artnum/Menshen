<?php

namespace Menshen;

require('GenericUser.php');
  /* == DB ==
     CREATE TABLE IF NOT EXISTS "menshen" ("clientid" INTEGER PRIMARY KEY AUTO_INCREMENT, "pkcs8" TEXT NOT NULL);
   */  
class PDOStore implements CertStore {
    protected $db;
    protected $tname;
    
    function __construct($pdoConn, $tableName) {
      $this->db = $pdoConn;
      $this->tname = $tableName;
    }

    function init() { return true; }

    function beginCheck() { return true; }

    function endCheck($clientId, $success) { return true; }

    function getUser($clientId) {
      $st = $this->db->prepare('SELECT * FROM "' . $this->tname . '" WHERE "clientid" = :cid');
      $st->bindParam(':cid', $clientId, \PDO::PARAM_INT);
      $person = [
        'uid' => $clientId,
        'certificate' => null
      ];
      if ($st->execute()) {
        if (($row = $st->fetch()) !== false) {
          $person['certificate'] = $row['pkcs8'];
        }
      }

      return new GenericUser($person);
    }  
}