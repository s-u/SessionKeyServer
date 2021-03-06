 SessionKeyServer
------------------

This is an implementation of a simple web-service that generates and
stores session keys/tokens. The current implementation is written in
Java.

    Usage: SessionKeyServer [-d <db-path>] [-l <address>] [-p <port>] [-pam-app <name>]
                            [-default <module>] [-jaas <jaas.conf> [-krb5conf <krb5.conf>]]
                            [-tls <keystore> [-P <password>] [-PF <password file location>] [-PP]]

By default the server listens on port 4431 and binds on `*`
If no database is specified, keys will be only kept in memory and
thus lost when the process dies.

The default authentication module is PAM and it can be changed using the `-default` parameter.
The `-pam-app` option can be used to override the application to report to PAM when authenticating,
the default is to use the realm supplied in the request, but sometimes app-based authentication is not
configured in the system and `-pam-app login` is a viable fall back to login authentication.

Any module other than PAM is routed to JAAS. If JAAS is used, it is possible to set necessary
properties either via Java's `-D` on invocation or there are two convenience options `-jaas` for
`java.security.auth.login.config` and `-krb5conf` for `java.security.krb5.conf`.


Supported requests:

    GET  /valid?realm=<realm>&token=<token>

Response: `text/plain`

    <result>
    [<user>]
    [<source>]

`<result>`  is one of NO, YES or SUPERCEDED:

`NO`          invalid (no further content added)

`YES`         valid and verified, user ID (attuid) is provided

`SUPERCEDED`  the token used to be valid, but it has been superceded by
            a new token, user ID (attuid) is also supplied

`<user>`   is the user id supplied by the source
`<source>` is the source that provided the authentication (i.e. the
	   method)


    GET  /revoke?realm=<realm>&token=<token>

Response: `text/plain`

    <result>

`<result>` is one of:

`OK`       token revoked successfully
`INVALID`  token is invalid

Note that it is legal to revoke a superceded token.


    GET  /replace?realm=<realm>&token=<token>

Response: `text/plain`

    <new token>
    <user>
    <source>

Replaces a given token (if valid) by a newly generated token. The
supplied token becomes invalid and only the new token is valid.
The request fails with 403 error code if the supplied token is not
valid.


    GET   /auth_token?realm=<realm>&user=<user>&pwd=<password>[&module=<module>]

Response: `text/plain`

    <token>
    <user>
    <source>

Requests authentication using the module specified or if not specified
whatever module is configured to be the default module on the server.
For `/auth_token` requests the source is defined as `auth/<module>`.


Note that requesting a new token in the same realm for the same user
will supercede all previous tokens.

The `<realm>` is mandatory for all requests and can be an arbitrary
string that identifies the realm in which this token will be valid.

### TLS/SSL mode

When `-tls` is specified on the command line it must point to a valid
Java key store file which will be used to load the private key and
certificate(s) for the secure HTTP server (aka HTTPS). The keys and
keystore password is set by default to `"SessionKeyServer"`, but can
also be specified via the `-P` option or entered at the command line
if `-PP` (password prompt) is specified. Obviously, if either the
default password or `-P` is used the key security is left to the
filesystem and the password does not provide additional protection.
Alternatively `-PF` allows the password to be read from a file in a keytab fashion
which then needs to be protected by 400 or 600.

If you have existing PEM key and certificate (e.g. for use in Rserve),
you can create Java keystore out of it via PKCS12 bundle as
follows. First, concatenate any intermediate certificates into one
file - from the server cert to the root cert, e.g.:

    cat /data/rcloud/conf/server.crt /data/rcloud/conf/verisign.crt > CA-chain.crt

Then create PKCS12 bundle:

    openssl pkcs12 -export -inkey /data/rcloud/conf/server.key -in CA-chain.crt -out server.pkcs12

Use `SessionKeyServer` as the password (unless you want to enter it by
hand at each start). Then create a keystore out of that:

    keytool -importkeystore -srckeystore server.pkcs12 -srcstoretype PKCS12 -destkeystore keystore    

Make sure you use the same password you used for the key. When done,
make sure you adjust the permissions such that only the user running
SKS can read the keystore (and remote the intermediate pkcs12
file). Now you can use `-tls keystore` option to run the
SessionKeyServer in TLS/SSL mode.


### Implementation details

Those details may change at any time, they are not guaranteed. The
current implementation uses SHA-1 hashes for tokens and internal
representation of realms. The token is a hash of a random UUID and the
decoded ESSec string.
