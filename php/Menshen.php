<?PHP

namespace {
  require('phpseclib/autoload.php');
  class Menshen {
    protected $certStore;
    protected $version = 1;
    
    function __construct($store) {
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
}

namespace Menshen {
  interface CertStore {
    public function init();
    public function beginCheck();
    public function endCheck($clientId, $success);
    public function getUser($clientId);
  }

  interface User {
    public function getUid();
    public function getDbId();
    public function getDisplayName();
    public function toJson();
  }

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

  class LDAPStore implements CertStore {
    protected $conn;
    protected $base;
    
    function __construct($ldap, $base) {
      $this->conn = $ldap;
      $this->base = $base;
    }

    function init() { return true; }
    function beginCheck() { return true; }
    function endCheck($clientId, $success) { return true; }
    function getUser($clientId) {
      $fclientId = ldap_escape($clientId, '', LDAP_ESCAPE_FILTER);
      $filter = sprintf('(&(|(uid=%s)(x500uniqueIdentifier=%s)(cn=%s)(mail=%s)(sn=%s))(|(usersmimecertificate=*)(userpkcs12=*)))', $fclientId, $fclientId, $fclientId, $fclientId, $fclientId);
      $res = @ldap_search(
        $this->conn,
        $this->base,
        $filter,
        [ 'sn', 'mail', 'uid', 'x500uniqueIdentifier', 'cn', 'userCertificate', 'userSMIMECertificate', 'userPKCS12', 'displayName' ],
        0,
        1
      );
      if (!$res) { return false; }
      $entry = @ldap_first_entry($this->conn, $res);
      if (!$entry) { return false; }
      return $this->parse_entry($entry);
    }

    function getUserByDbId ($dbId) {
      $res = @ldap_read(
        $this->conn,
        $dbId,
        '(|(usersmimecertificate=*)(userpkcs12=*))',
        [ 'sn', 'mail', 'uid', 'x500uniqueIdentifier', 'cn', 'userCertificate', 'userSMIMECertificate', 'userPKCS12', 'displayName' ],
        0
      );
      if (!$res) { return false; }
      $entry = @ldap_first_entry($this->conn, $res);
      if (!$entry) { return false; }
      return $this->parse_entry($entry);
    }

    function parse_entry($entry) {
      $person = [
        'certificate' => null,
        'displayname' => null,
        'uid' => null,
        'dbid' => @ldap_get_dn($this->conn, $entry)
      ];
      if (!$person['dbid']) { return false; }

      for ($attr = @ldap_first_attribute($this->conn, $entry); $attr; $attr = @ldap_next_attribute($this->conn, $entry)) {
        switch(strtolower($attr)) {
          case 'usercertificate':
            $val = @ldap_get_values_len($this->conn, $entry, $attr);
            if (!$val) { break; }
            if ($val['count'] > 0) {
              $person['certificate'] = $val[0];
            }
            break;
          case 'usersmimecertificate':
          case 'userpkcs12':
            /* userCertificate is prefered and set anyway */
            if ($person['certificate']) { break; }
            $val = @ldap_get_values($this->conn, $entry, $attr);
            if (!$val) { break; }
            if ($val['count'] > 0) {
              $person['certificate'] = $val[0];
            }
            break;
          case 'uid':
            $val = @ldap_get_values($this->conn, $entry, $attr);
            if (!$val) { break; }
            if ($val['count'] > 0) {
              $person['uid'] = $val[0];
            }
            break;
          case 'sn':
          case 'mail':
          case 'cn':
            $val = @ldap_get_values($this->conn, $entry, $attr);
            if (!$val) { break; }
            if ($val['count'] > 0) {
              if (!$person['uid']) {
                $person['uid'] = $val[0];
              }
              if (!$person['displayname']) {
                $person['displayname'] = $val[0];
              }
            }
            break;
          case 'x500uniqueidentifier':
            if ($person['uid']) { break; }
            $val = @ldap_get_values_len($this->conn, $entry, $attr);
            if (!$val) { break; }
            if ($val['count'] > 0) {
              $person['uid'] = $val[0];
            }
            break;
          case 'displayname':
            $val = @ldap_get_values($this->conn, $entry, $attr);
            if (!$val) { break; }
            if ($val['count'] > 0) {
              $person['displayname'] = $val[0];
            }
            break;
        }
      }
      return new GenericUser($person);
    }
  }
}
?>
