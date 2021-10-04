<?php

namespace Menshen;

interface CertStore {
    public function init();
    public function beginCheck();
    public function endCheck($clientId, $success);
    public function getUser($clientId);
  }