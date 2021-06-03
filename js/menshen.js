/* eslint-env browser, worker */
const MenshenEncoding = {
  base64Decode: (t) => {
    try {
      const s = atob(t.trim().replace(/\r?\n|\r/g, ''))
      const b = new ArrayBuffer(s.length)
      const v = new Uint8Array(b)
      for (let i = 0; i < s.length; i++) {
        v[i] = s.charCodeAt(i)
      }
      return b
    } catch (e) {
      return null
    }
  },

  base64Encode: (b) => {
    try {
      let t = ''
      const s = btoa(String.fromCharCode.apply(null, new Uint8Array(b)))
      for (let i = 0; i < (Math.ceil(s.length / 64)); i++) {
        t += s.substring(i * 64, (i + 1) * 64) + '\n'
      }
      return t
    } catch (e) {
      return null
    }
  },

  hex2buf: (text) => {
    let buf = new Uint8Array(text.length / 2)
    let x = 0
    for (let i = 0; i < text.length; i++) {
      switch (text[i]) {
        case '0': break
        case '1': x |= 1; break
        case '2': x |= 2; break
        case '3': x |= 3; break
        case '4': x |= 4; break
        case '5': x |= 5; break
        case '6': x |= 6; break
        case '7': x |= 7; break
        case '8': x |= 8; break
        case '9': x |= 9; break
        case 'A': case 'a': x |= 0x0a; break
        case 'B': case 'b': x |= 0x0b; break
        case 'C': case 'c': x |= 0x0c; break
        case 'D': case 'd': x |= 0x0d; break
        case 'E': case 'e': x |= 0x0e; break
        case 'F': case 'f': x |= 0x0f; break
        default: return null
      }
      if ((i + 1) % 2 === 0) {
        buf[i >> 1] = x
        x = 0
      }
      x <<= 4
    }
    return buf
  },

  buf2hex: (buffer) => {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
  },
  
  btoa: (value) => {
    return btoa(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '.')
  },

  buf2b64: (buffer) => {
    var binary = ''
    var bytes = new Uint8Array( buffer )
    var len = bytes.byteLength
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] )
    }
    return MenshenEncoding.btoa( binary )
  },

  readPEM: (c) => {
    const pemRegex = /^\s*-----BEGIN (PRIVATE|PUBLIC) KEY-----$([a-zA-Z0-9/+=\r\n]*)^-----END (?:PRIVATE|PUBLIC) KEY-----\s*$/mg
    const m = pemRegex.exec(c)
    if (m && m.length > 1) {
      return {cert: MenshenEncoding.base64Decode(m[2]), privkey: m[1] === 'PRIVATE'}
    }
    return false
  },

  writePEM: (c, p = false) => {
    let t = `-----BEGIN ${p ? 'PRIVATE' : 'PUBLIC'} KEY-----\n`
    t += MenshenEncoding.base64Encode(c)
    return t + `-----END ${p ? 'PRIVATE' : 'PUBLIC'} KEY-----\n`
  }
}

const MenshenRSAUtils = {
  sign: (privkey, text, options = {saltLength: 0, hash: 'SHA-256', raw: false}) => {
    return new Promise((resolve, reject) => {
      if (!privkey) { resolve(false); return }
      crypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength: options.saltLength,
          hash: {
            name: options.hash
          }
        },
        privkey,
        (new TextEncoder()).encode(text))
        .then((signed) => {
          if (options.raw) {
            resolve(signed)
          } else {
            resolve(MenshenEncoding.base64Encode(signed))
          }
        })
    })
  },

  verify: (pubkey, text, sign, options = {raw: false, hash: 'SHA-256', saltLength: 0}) => {
    return new Promise((resolve, reject) => {
      if (!pubkey) { resolve(false); return }
      if (!options.raw) {
        sign = MenshenEncoding.base64Decode(sign)
      }
      if (!sign) { resolve(false); return }
      crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength:
          options.saltLength,
          hash: {
            name: options.hash
          }
        },
        pubkey,
        sign,
        (new TextEncoder()).encode(text)
      )
      .then((v) => { resolve(v) })
    })
  }
}

function MenshenKeyStore () {
  this.IDB = null
}

MenshenKeyStore.prototype.init = function () {
  this._init = new Promise((resolve, reject) => {
      const request = indexedDB.open('MenshenKeyStore', 1)
      request.onupgradeneeded = (event) => {
          const idb = event.target.result
          if (!idb.objectStoreNames.contains('keystore')) {
            idb.onsuccess = (event) => {
              resolve(idb)
            }
            idb.createObjectStore('keystore', {keyPath: 'k'})
          } else {
            resolve(idb)
          }
      }

      request.onsuccess = (event) => {
          resolve(event.target.result)
      }
  })
  return this._init
}

MenshenKeyStore.prototype.eraseAuth = function (nick) {
  return new Promise((resolve, reject) => {
      this.init()
      .then(idb => {
        const transaction = idb.transaction('keystore', 'readwrite')
        const request = transaction.objectStore('keystore').clear()
        request.onerror = (event) => { reject(event.message) }
        request.onabort = (event) => { resolve() }
        request.oncomplet = (event) => { resolve() }
      })
  })
}

MenshenKeyStore.prototype.getAuth = function () {
  return new Promise((resolve, reject) => {
    this.init()
    .then(idb => {
      const transaction = idb.transaction('keystore', 'readonly')
      const request = transaction.objectStore('keystore').get('current')
      request.onsuccess = event => resolve(event.target.result)
      request.onerror = event => reject(event.target.error)
      transaction.onabort = event => resolve()
    })
  })
}

MenshenKeyStore.prototype.importPrivateKey = function (INKey, clientId, nickName, hash, opts = {}) {
  return new Promise((resolve, reject) => {
    const key = MenshenEncoding.readPEM(INKey)

    if (key && !key.privkey) { reject(new Error('Key is not private')); return }
    
    crypto.subtle.importKey(
      'pkcs8',
      key?.cert || INKey, // either we have a PEM encoded or we have something we can try to pass
      { name: 'RSA-PSS', hash: { name: hash } },
      false,
      ['sign']
    )
    .then((k) => {
      return this.storeAuth(nickName, clientId, k, opts)
    })
    .then(() => {
      resolve()
    })
    .catch(reason => {
      reject(reason)
    })
  })
}

MenshenKeyStore.prototype.storeAuth = function (nick, cid, pkey, opts = {}) {
  return new Promise((resolve, reject) => {
      if (!pkey instanceof CryptoKey) {
          reject('Not a cryptokey')
          return
      }
    this.init()
    .then(idb => {
      const transaction = idb.transaction('keystore', 'readwrite')

      transaction.onerror = event => reject(new Error(event.message))
      transaction.onabort = event => resolve()
      transaction.oncomplete = event => { resolve() }

      transaction.objectStore('keystore').put({
          k: 'current',
          nick: nick,
          cid: cid,
          pkey: pkey,
          opts: opts
      })
    })
  })
}

const GLOBAL = new Function('return this')()

function Menshen (options = {}, _fetch = null) {
  this.version = 1
  if (options.version === 2) {
    this.version = 2
  }
  if (_fetch !== null) {
    this.fetchFunction = _fetch
  } else {
    this.fetchFunction = GLOBAL.fetch
  }
  this.kloaded = false
  this.saltLength = 0
  this.hash = 'SHA-256'
  this.key = { priv: null, pub: null }
  if (options.privkey) {
    this.loadKey(options.privkey)
  }
  if (options.pubkey) {
    this.loadKey(options.pubkey)
  }
  if (options.hash) {
    this.setHash(options.hash)
  }
  if (options.salt) {
    this.setSaltLength(options.salt)
  }
}

Menshen.prototype.isLoaded = function () {
  if (this._isLoaded === undefined) {
    return new Promise((resolve, reject) => { reject(new Error('No attempt to load key done')) })
  }
  return this._isLoaded
}

Menshen.prototype.loadKey = function (txt) {
  return new Promise((resolve, reject) => {
    let k = MenshenEncoding.readPEM(txt)
    if (k) {
      if (k.privkey) {
        crypto.subtle.importKey(
          'pkcs8',
          k.cert,
          { name: 'RSA-PSS', hash: { name: this.hash } },
          false,
          ['sign']
        )
        .then(
          (k) => {
            this.key.priv = k
            this.kloaded = true
            resolve(this.key.priv)
          }
        )
      } else {
        crypto.subtle.importKey(
          'spki',
          k.cert,
          { name: 'RSA-PSS', hash: { name: this.hash } },
          false,
          ['verify']
        )
        .then(
          (k) => {
            this.key.pub = k
            this.kloaded = true
            resolve(this.key.pub)
          }
        )
      }
    }
  })
}

Menshen.prototype.setClientId = function (cid) {
  this.clientid = cid
}

Menshen.prototype.getClientId = function () {
  return this.clientid
}

Menshen.prototype.setPrivateKey = function (key) {
  if (!key instanceof CryptoKey) { return }
  if (key.type !== 'private') { return }
  this.key.priv = key
  this.kloaded = true
}

Menshen.prototype.setPublicKey = function (key) {
  if (!(key instanceof CryptoKey)) { return }
  if (!key.type !== 'public') { return }   
  this.key.pub = key
}

Menshen.prototype.getPrivateKey = function () {
  return this.key.priv
}

Menshen.prototype.getPublicKey = function () {
  return this.key.pub
}

Menshen.prototype.getHashLength = function (h, bytes = true) {
  switch (h.toLowerCase()) {
    default: return -1
    case 'sha1': case 'sha-1':
      return bytes ? 160 >> 3 : 160
    case 'sha256': case 'sha-256':
      return bytes ? 256 >> 3 : 256
    case 'sha384': case 'sha-384':
      return bytes ? 384 >> 3 : 384
    case 'sha512': case 'sha-512':
      return bytes ? 512 >> 3 : 512
  }
}

Menshen.prototype.setHash = function (h) {
  if (this.kloaded) { console.error('Hash must be set before key is loaded'); return }
  switch (h.toLowerCase()) {
    case 'sha1': case 'sha-1':
      this.hash = 'SHA-1'; break
    case 'sha256': case 'sha-256':
      this.hash = 'SHA-256'; break
    case 'sha384': case 'sha-384':
      this.hash = 'SHA-384'; break
    case 'sha512': case 'sha-512':
      this.hash = 'SHA-512'; break
  }
}

Menshen.prototype.getHash = function () {
  return this.hash
}

/* MHash : Menshen want alphanumeric lower case only */
Menshen.prototype.getMHash = function () {
  switch (this.getHash()) {
    case 'SHA-1':
      return 'sha1'
    case 'SHA-256':
      return 'sha256'
    case 'SHA-384':
      return 'sha384'
    case 'SHA-512':
      return 'sha512'
  }
}

Menshen.prototype.getSaltLength = function () {
  return this.saltLength
}

Menshen.prototype.setSaltLength = function (len) {
  len = parseInt(len)
  if (isNaN(len) || len === 0) { this.saltLength = 0 }
  else {
    /* We max salt length to digest output size */
    if (len < 0) {
      len = this.getHashLength(this.hash)
    } else {
      let hLen = this.getHashLength(this.hash)
      if (hLen < len) { len = hLen }
    }
    this.saltLength = len
  }
}

Menshen.prototype.getMID = function (method, url, reqid) {
  return new Promise((resolve, reject) => {
    switch (this.version) {
      case 1:
        resolve(`${method.trim().toLowerCase()}|${url}|${reqid.trim().toLowerCase()}`)
        break
      case 2:
        crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(reqid),
          {
            name: 'HMAC',
            hash: {name: 'SHA-256'}
          },
          false,
          [ 'sign' ]
        ).then(key => {
          return crypto.subtle.sign(
            {name: 'HMAC'},
            key, 
            new TextEncoder().encode(`${method.trim().toLowerCase()}${url}`)
          )
        })
        .then(buffer => {
          resolve(MenshenEncoding.buf2b64(buffer))
        })
        break
      default:
        reject(new Error('Version unknown'))
        break
    }
  })
}

Menshen.prototype.authValues = function (clientid, method, query, qid) {
  return new Promise((resolve, reject) => {
    const authValues = {
      type: this.version === 1 ? 'Menshen' : 'Menshen2',
      cid: this.version === 1 ? clientid : MenshenEncoding.btoa(clientid),
      sle: this.getSaltLength(),
      dgt: this.getHash()
    }
    this.getMID(method, query, qid)
    .then(mid => {
      return MenshenRSAUtils.sign(
        this.getPrivateKey(),
        mid,
        {
          hash: authValues.hash,
          saltLength: authValues.sle,
          raw: true
        }
      )
    })
    .then(signed => {
      authValues.sig = MenshenEncoding.buf2b64(signed)
      return authValues
    })
    .then(authValues => {
      resolve(authValues)
    })
    .catch(reason => reject(reason))
  })
}

Menshen.prototype.qstring = function (url, method, requestId) {
  return new Promise((resolve, reject) => {
    this.authValues(this.clientid, method, url.host, requestId)
    .then(authValue => {
      url.searchParams.append('menshen_qid', requestId)
      for(const k in authValue) {
        url.searchParams.append(`menshen_${k}`, authValue[k])
      }
      resolve(url)
    })
  })
}

Menshen.prototype.fetch = function (url, params) {
  return new Promise((resolve, reject) => {
    if (!(url instanceof URL)) {
      url = new URL(url)
    }
    const query = String(url.pathname + url.search)
    let method = 'get'
    if (params === undefined) {
      params = {}
    }
    if (params.method !== undefined) {
      method = params.method.toLowerCase()
    }
    if (params.headers === undefined) {
      params.headers = new Headers()
    }
    if (!(params.headers instanceof Headers)) {
      let headers = new Headers()
      for (let k in params.headers) {
        headers.append(k, params.headers[k])
      }
      params.headers = headers
    }

    let qid = ''
    if (params.headers.has('X-Request-Id')) {
      qid = params.headers.get('X-Request-Id')
    } else {
      qid =`${new Date().getTime()}-${performance.now()}`
      params.headers.append('X-Request-ID', qid)
    }
    
    this.authValues(this.clientid, method, query, qid)
    .then(authValues => {
      params.headers.set('Authorization', `${authValues.type} cid=${authValues.cid},sig=${authValues.sig},sle=${authValues.sle},dgt=${authValues.dgt}`)
      return fetch(url, params)
    })
    .then(response => {
      resolve(response)
    })
    .catch(reason => reject(reason))
  })
}