<?php

namespace Menshen;

class GenericUser implements User {
    private $displayName = null;
    private $dbId = null;
    private $uid = null;
    private $certificate = null;

    function __construct($init = []) {
      foreach($init as $k => $v) {
        switch ($k) {
          case 'dbid': $this->setDbId($v); break;
          case 'uid': $this->setUid($v); break;
          case 'displayname': $this->setDisplayName($v); break;
          case 'certificate': $this->setCertificate($v); break;
        }
      }
    }

    function toJson () {
      return json_encode([
        'name' => $this->getDisplayName(),
        'uid' => $this->getUid(),
        'dbid' => $this->getDbId(),
        'certificate' => $this->getStrCertificate()
      ]);
    }

    function setDisplayName($name) {
      $this->displayName = $name;
    }
    function setDbId($id) {
      $this->dbId = $id;
    }
    function setUid($id) {
      $this->uid = $id;
    }
    function setCertificate($certificate) {
      $this->certificate = $certificate;
    }
    function getDisplayName() {
      if ($this->displayName === null) { return ''; }
      return  $this->displayName;
    }
    function getDbId() {
      if ($this->dbId === null) { return ''; }
      return $this->dbId;
    }
    function getUid() {
      if ($this->uid === null) { return ''; }
      return $this->uid;
    }
    function getStrCertificate() {
      if ($this->certificate === null) { return ''; }
      if (preg_match('/.*BEGIN.*/', $this->certificate)) { // some BEGIN from pem encoded, its string
        return $this->certificate;
      } else {
        return base64_encode($this->certificate); // binary cert, encode
      }
    }
    function getCertificate() {
      if ($this->certificate === null) { return ''; }
      return $this->certificate;
    }
  }