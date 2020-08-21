In a Nutshell
=============

A client library maintaining valid OAUTH2 client token as background
operation.


Reference
=========

```
const DOC = require('tr-oauth2');

var doc = new DOC('https://oauth2-auth-server.in.my.domain/oauth/token',
                  { grant_type: 'client_credentials' },
		  'my-username',
		  'my-very-secret-password');
doc.on('refresh', function(expiresIn) { console.log('Token refreshed.'); });
doc.on('error', function(e) { console.log(e); process.exit(1); });
```

In your code, you'll want to wait for the first `refresh`
callback. After this, if everything works, `doc.token` will
automatically be maintained so that it points to a valid token.

Server
======

While this package is mainly a client library maintaining a valid
OAUTH2 token for some other use, there is also actually a fully
functional OAUTH2 server that can yield access tokens for clients and
can also handle token verification and revocation. User database is a
CSV file (example in users.dat) and can contain also scopes and
authorities. The token is a JWT token which is either signed with RSA
key or using a static symmetric secret.

This is not really aimed for serious production use and it also
naturally needs a HTTPS termination service (such as a nginx reverse
proxy) in front of itself. However if someone spots a security
problem, please report them so I can fix or document them.

```
Usage:
  oauthserver [<opt> ...]
  Options:
       --listen-address=<arg>   IP address the server listens to.
       --listen-port=<arg>      TCP port the server listens to.
       --token-ttl=<arg>        Default validity time for tokens in seconds.
       --token-issuer=<arg>     Issuer name to be included into tokens.
       --users-file=<arg>       CSV file containing users data.
       --secret-key-file=<arg>  Read token signing key from file.
       --public-key-file=<arg>  Read token verifying key from file.
       --secret=<arg>           Symmetric secret for token signing.
       --secret-file=<arg>      Read symmetric secret from file.
   -h  --help                   Show help and exit
```


Author
======

Timo J. Rinne <tri@iki.fi>


License
=======

UNLICENSED
