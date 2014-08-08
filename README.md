This is an attempt at a new auth scheme for HTTP, based on RFC7235. The
goal is to keep the scheme easy for the user (only a password) and
remove the risks (the password isn't sent nor stored in the server).

Note that contrary to SRP, this is intended to be used in HTTP, not in
the layer under.

Here's the flow (C = Client, S = Server) :

## Registering

- C: generate a random salt, calculate its hmac-sha256 with the password
  as key, and use this material to derive a ed25519 private/public signing
  key pair. This public key will be used as the identifier on the
  Server.

- C -> S: send salt, public key and username (not yet implemented)

    POST /register?pub=0ad5114bbf1b795fb4cb9523d623e55714edd39b42c6e1a2b564fbb23b391541&salt=69abb3a48507ca30bad3eddd13dfac58bfa9b975 HTTP/1.1\r\n

- S: store public key and salt

## Signing in

- C: Ask for salt. Normally you would use your username to identify
  yourself, here we use public key (which shouldn't be possible):


    GET /session HTTP/1.1
    Host: localhost:8888
    Pub: 0ad5114bbf1b795fb4cb9523d623e55714edd39b42c6e1a2b564fbb23b391541

  (Note: using a raw Pub header isn't the best solution)

- S -> C: send back the salt along with a challenge and a 401


    HTTP/1.1 401 Unauthorized
    Www-Authenticate: Challenge salt=69abb3a48507ca30bad3eddd13dfac58bfa9b975, challenge=fb337d6f1e9bbfe113a930a36c4b4b07b1c970cb
    Date: Fri, 08 Aug 2014 18:31:22 GMT
    Content-Length: 0
    Content-Type: text/plain; charset=utf-8

- C: re-generate private/public key pair with salt and password, sign
  the challenge and send it to the server:


    GET /session HTTP/1.1
    Host: localhost:8888
    Authorization: Challenge challenge=fb337d6f1e9bbfe113a930a36c4b4b07b1c970cb, response=004f73626a1f0b459b4ad3be710b7e4869fc015162d787a6a45fc1a93952c462c2bf78ff533e276cff2238e275906ee7e6a29eb5d9af9917d3426220498d4708, pub=0ad5114bbf1b795fb4cb9523d623e55714edd39b42c6e1a2b564fbb23b391541
    Accept-Encoding: gzip

- S: Verify the response, auth if possible.


To test:

- Run main.go in a terminal:

    $ go run main.go

- Run client/main.go in another terminal with a password:

    $ cd client
    $ go run main.go <password>
