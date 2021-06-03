# Menshen

Authentication mechanism for the web using private/public key pair.

## Stateless

This mechanism is not meant to provide a secure session, only authenticated request. The client use the HTTP header Authorization to add relevant information about the signature. Signature are RSA-PSS, most parameters can be tuned by the client.
The server handle only a "client id" and the associate public key.

## Privacy

The client never need to share the private key with the server. The client handle its private key as it sees fit.$

## Simple

As the server just need to hash some header and verify it against a given signature, it can be added easly on almost anything without too much modification. As the private key can be in a file, embbed in an URL or a QR Code, it can provide a password-less experience for the user. Once the user register, he received a link with embbed private key. On the first log in, a new pair is generated, the public key is sent to the server, the private one is stored in the IndexedDB of the navigator and a quite secure authentication is set.
A password on the private key can be, of course, set for added security.