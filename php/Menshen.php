<?PHP

class Menshen {
  protected $certStore;
  protected $version = 1;
  
  function __construct(Menshen\CertStore $store) {
    $this->Auth = [];
    $this->certStore = $store;
    $this->certStore->init();
  }
  
  function check() {
    try {
      if (!$this->certStore->beginCheck()) { return false; }

         $auth = $this->getAuth();
      if (empty($auth)) { return false; }
      
      $user = $this->certStore->getUser($auth['cid']);
      if (!$user) { return false; }
      if (!$user->getCertificate()) { return false; }
      $rsa = new \phpseclib\Crypt\RSA();

      if(!$rsa->loadKey($user->getCertificate())) { return false; }

      $mid = $this->getMID();
      if (empty($mid)) { return false; }

      $rsa->setHash($auth['dgt']);
      $rsa->setMGFHash($auth['mgf']);
      $rsa->setSaltLength($auth['sle']);
      $rsa->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PSS);

      $success = $rsa->verify($mid, $auth['sig']);
      if (!$this->certStore->endCheck($auth['cid'], $success)) { return false; }

      if ($success) {
        return $user;
      }
      return false;
    } catch (Exception $e) {
      error_log('Menshen::"' . $e->getMessage() . '"');
      return false;
    }   
  }
  
  public function getCID() {
    if (empty($this->Auth)) { return null; }
    if (empty($this->Auth['cid'])) { return null; }
    return $this->Auth['cid'];
  }

  public function b64decode($txt) {
    return base64_decode(str_replace(['-', '_', '.'], ['+', '/', '='], $txt));
  }

  public function b64encode($raw) {
    return str_replace(['+', '/', '='], ['-', '_', '.'], base64_encode($raw));
  }

  protected function getAuthValue ($name, $rawValue) {
    switch($name) {
      case 'qid':
        return $rawValue;
      case 'cid':
        switch($this->version) {
          default: return null;
          case 1:
            return $rawValue;
          case 2:
            return $this->b64decode($rawValue);
        }
        break;
      case 'sle':
        return intval($rawValue);
      case 'sig':
        switch($this->version) {
          default: return null;
          case 1:
            return hex2bin($rawValue);
          case 2:
            return $this->b64decode($rawValue);
        }
        break;
      case 'mgf':
      case 'dgt':
        $rawValue = strtolower($rawValue);
        switch ($rawValue) {
          case 'md2':
          case 'md5':
          case 'sha1':
          case 'sha256':
          case 'sha384':
          case 'sha512':
            return $rawValue;
          case 'sha-256':
            return 'sha256';
          case 'sha-384':
            return 'sha384';
          case 'sha-512':
            return 'sha512';
        }
      default: return null;
    }
  }

  protected function getQSAuth () {
    $args = [
      'cid' => false, /* client id */
      'sig' => false, /* signature */
      'dgt' => 'sha256', /* digest */
      'sle' => 0, /* saltlen */
      'mgf' => 'sha256',
      'sig' => false,
      'qid' => false
    ];

    if (!isset($_REQUEST['menshen_type'])) { return[]; }

    switch(strtolower($_REQUEST['menshen_type'])) {
      case 'menshen': $this->version = 1; break;
      case 'menshen2': $this->version = 2; break;
      default: return [];
    }
    
    foreach ($_REQUEST as $k => $v) {
      if (strpos($k, 'menshen_') === 0) {
        $k = substr($k, 8);
        if ($k === 'type') { continue; }
        if (isset($args[$k])) {
          $args[$k] = $this->getAuthValue($k, $v);
          if ($args[$k] === null) { return []; }
        }
      }
    }

    if ($args['cid'] === false || $args['sig'] === false) { return []; }
    $this->Auth = $args;
    return $args;
  }

  protected function getAuth () {
    if (!empty($this->Auth)) { return $this->Auth; }

    $args = [
      'cid' => false, /* client id */
      'sig' => false, /* signature */
      'dgt' => 'sha256', /* digest */
      'sle' => 0, /* saltlen */
      'mgf' => 'sha256',
      'sig' => false
    ];

    if (empty($_SERVER['HTTP_AUTHORIZATION'])) { return $this->getQSAuth(); }

    $version = 1;
    $auth = trim($_SERVER['HTTP_AUTHORIZATION']);
    if (strncasecmp($auth, 'menshen', 7) !== 0) { return []; }
    if ($auth[7] === '2') { $version = 2; }
    $this->version = $version; 

    $authstr = explode(',', substr($auth, $version === 1 ? 7 : 8));

    foreach ($authstr as $p) {
      if (strpos($p, '=') === -1) { return[]; }
      list ($k, $v) = explode('=', $p, 2);
      $k = trim($k);
      $v = trim($v);
      $args[$k] = $this->getAuthValue($k, $v);
      if ($args[$k] === null) { return []; }
    }
    if ($args['cid'] === false || $args['sig'] === false) { return []; }
    $this->Auth = $args;
    return $args;
  }
  
  public function getMID () {
    if (
      empty($_SERVER['REQUEST_METHOD']) || 
      empty(isset($this->Auth['qid']) ? $this->Auth['qid'] : $_SERVER['HTTP_X_REQUEST_ID']) ||
      empty($_SERVER['REQUEST_URI'])
    ) {
      return '';
    }

    switch ($this->version) {
      case 1:
        return sprintf(
          '%s|%s|%s',
          strtolower(trim($_SERVER['REQUEST_METHOD'])),
          isset($this->Auth['qid']) ? $_SERVER['HTTP_HOST'] : $_SERVER['REQUEST_URI'],
          strtolower(trim(isset($this->Auth['qid']) ? $this->Auth['qid'] : $_SERVER['HTTP_X_REQUEST_ID']))
        );
      case 2:
        return $this->b64encode(
          hash_hmac(
            'sha256',
            strtolower(trim($_SERVER['REQUEST_METHOD'])) . (isset($this->Auth['qid']) ? $_SERVER['HTTP_HOST'] : $_SERVER['REQUEST_URI']),
            isset($this->Auth['qid']) ? $this->Auth['qid'] : $_SERVER['HTTP_X_REQUEST_ID'],
          true)
        );
    }
    return '';
  }
}

?>
