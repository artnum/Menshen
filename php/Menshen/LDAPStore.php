<?php

namespace Menshen;

require('GenericUser.php');

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