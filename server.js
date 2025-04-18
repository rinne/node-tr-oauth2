'use strict';

module.exports = function() {

	const http = require('node:http');
	const crypto = require('node:crypto');
	const qs = require('node:querystring')
	const fs = require('node:fs');
	const path = require('node:path');
	const jwt = require('jsonwebtoken');
	const jwk = require('pem-jwk');
	const Optist = require('optist');
	const ou = require('optist/util');

	const userFileRead = require('./userfileread');
	const clientFileRead = require('./clientfileread');
	const template = require('./template');

	/*
	  If tokens must remain valid over restart, define secret as a random
	  string and keep it secret. Otherwise a random secret is created
	  automatically every time the program starts. Alternatively, use
	  a keypair, which in most cases is the correct answer anyways.
	*/

	var context = {
		debug: false,
		users: new Map(),
		clients: null,
		jtRevocation: new Map(),
		jtLogout: new Map(),
		jwtConf: {},
		staticContent: new Map(),
	};

	async function delay(ms) {
		return new Promise(function (resolve, reject) { setTimeout(resolve, ms); });
	}

	function ts() {
		return new Date().toISOString().slice(0, 19).replace('T', ' ');
	}

	function log(...av) {
		console.log((ts() + ':'), ...av);
	}

	function debug(...av) {
		if (context.debug) {
			log(...av);
		}
	}

	function fatal(...av) {
		try {
			if (context.debug) {
				av.unshift((ts() + ':'));
			}
		} catch (e) {
			/*NOTHING*/
		}
		console.error(...av);
		process.exit(1);
	}

	function isArrayOfStrings(a) {
		return (Array.isArray(a) && (a.filter((x) => (typeof(x) !== 'string')).length == 0));
	}

	function readStaticContent() {
		let rv = true;
		try {
            let n = fs.realpathSync(path.dirname(fs.realpathSync(__filename)) + '/static-content');
			let d = fs.opendirSync(n);
			do {
				let f = d.readSync();
				if (! f) {
					break;
				}
				if (! f.isFile()) {
					continue;
				}
				context.staticContent.set(f.name, fs.readFileSync(fs.realpathSync(n + '/' + f.name), 'utf8'));
			} while(true);
			d.closeSync();
		} catch (e) {
			console.error(e);
			rv = false;
		}
		return rv;
	}

	var opt = ((new Optist())
			   .opts([ { longName: 'debug',
						 description: 'Debug mode.',
						 environment: 'TR_OAUTH2_OPT_DEBUG' },
					   { longName: 'listen-address',
						 description: 'IP address the server listens to.',
						 hasArg: true,
						 defaultValue: '127.0.0.1',
						 environment: 'TR_OAUTH2_OPT_LISTEN_ADDRESS',
						 optArgCb: ou.ipv4 },
					   { longName: 'listen-port',
						 description: 'TCP port the server listens to.',
						 hasArg: true,
						 defaultValue: '80',
						 environment: 'TR_OAUTH2_OPT_LISTEN_PORT',
						 optArgCb: ou.integerWithLimitsCbFactory(1, 65535) },
					   { longName: 'token-ttl',
						 description: 'Default validity time for tokens in seconds.',
						 hasArg: true,
						 defaultValue: '3600',
						 environment: 'TR_OAUTH2_OPT_TOKEN_TTL',
						 optArgCb: ou.integerWithLimitsCbFactory(1, 999999999999) },
					   { longName: 'token-issuer',
						 description: 'Issuer name to be included into tokens.',
						 hasArg: true,
						 defaultValue: 'anonymous',
						 environment: 'TR_OAUTH2_OPT_TOKEN_ISSUER',
						 optArgCb: ou.nonEmptyCb },
					   { longName: 'users-file',
						 description: 'CSV file containing users data.',
						 hasArg: true,
						 environment: 'TR_OAUTH2_OPT_USERS_FILE',
						 optArgCb: ou.existingFileNameCb,
						 required: true },
					   { longName: 'clients-file',
						 description: 'CSV file containing clients data.',
						 hasArg: true,
						 environment: 'TR_OAUTH2_OPT_CLIENTS_FILE',
						 optArgCb: ou.existingFileNameCb },
					   { longName: 'secret-key-file',
						 description: 'Read token signing key from file.',
						 hasArg: true,
						 environment: 'TR_OAUTH2_OPT_SECRET_KEY_FILE',
						 optArgCb: ou.fileContentsStringCb,
						 conflictsWith: [ 'secret', 'secret-file' ] },
					   { longName: 'public-key-file',
						 description: 'Read token verifying key from file.',
						 hasArg: true,
						 environment: 'TR_OAUTH2_OPT_PUBLIC_KEY_FILE',
						 optArgCb: ou.fileContentsStringCb,
						 requiresAlso: 'secret-key-file',
						 conflictsWith: [ 'secret', 'secret-file' ] },
					   { longName: 'secret',
						 description: 'Symmetric secret for token signing.',
						 hasArg: true,
						 environment: 'TR_OAUTH2_OPT_SECRET',
						 optArgCb: ou.nonEmptyCb,
						 conflictsWith: [ 'secret-key-file', 'public-key-file', 'secret-file' ] },
					   { longName: 'secret-file',
						 description: 'Read symmetric secret from file.',
						 hasArg: true,
						 environment: 'TR_OAUTH2_OPT_SECRET_FILE',
						 optArgCb: ou.fileContentsStringCb,
						 conflictsWith: [ 'secret-key-file', 'public-key-file', 'secret' ] } ])
			   .help('oauthserver')
			   .parse(undefined, 0, 0));

	context.debug = opt.value('debug') ? true : false;
	if (context.debug) {
		process.on("SIGUSR1", function() { debug('users:', context.users);
										   debug('clients:', context.clients);
										   debug('revocation:', context.jtRevocation);
										   debug('logout:', context.jtLogout); });
	}

	(function() {

		context.jwtConf.issuer = opt.value('token-issuer');
		context.jwtConf.defaultTTL = opt.value('token-ttl');
		if (opt.value('secret-key-file')) {
			try {
				context.jwtConf.secretKey = opt.value('secret-key-file');
				context.jwtConf.secretKeyJwk = jwk.pem2jwk(context.jwtConf.secretKey);
				if (opt.value('public-key-file')) {
					context.jwtConf.publicKey = opt.value('public-key-file');
					context.jwtConf.publicKeyJwk = jwk.pem2jwk(context.jwtConf.publicKey);
				} else {
					context.jwtConf.publicKeyJwk = { kty: context.jwtConf.secretKeyJwk.kty,
													 n: context.jwtConf.secretKeyJwk.n,
													 e: context.jwtConf.secretKeyJwk.e };
					context.jwtConf.publicKey = jwk.jwk2pem(context.jwtConf.publicKeyJwk);
					context.jwtConf.publicKeyJwk = jwk.pem2jwk(context.jwtConf.publicKey);
				}
				context.jwtConf.algorithm = 'RS256';
			} catch(e) {
				context.jwtConf.algorithm = undefined;
			}
			if (! context.jwtConf.algorithm) {
				fatal('Invalid public key pair');
			}
			context.jwtConf.keyId = (crypto
									 .createHash('sha256')
									 .update(JSON.stringify( { kty: context.jwtConf.publicKeyJwk.kty,
															   n: context.jwtConf.publicKeyJwk.n,
															   e: context.jwtConf.publicKeyJwk.e } ))
									 .digest('base64')
									 .replace(/[^a-zA-Z]/g, '')
									 .toLowerCase()
									 .slice(0, 12));
		} else if (opt.value('secret-file')) {
			context.jwtConf.algorithm = 'HS256';
			context.jwtConf.secret = opt.value('secret-file');
		} else if (opt.value('secret')) {
			context.jwtConf.algorithm = 'HS256';
			context.jwtConf.secret = opt.value('secret');
		} else {
			context.jwtConf.algorithm = 'HS256';
			context.jwtConf.secret = crypto.randomBytes(66).toString('base64');
		}
		try {
			(function(t, a, b) {
				a = { iss: context.jwtConf.issuer,
					  iat: Math.floor(Date.now() / 1000) - 60,
					  exp: Math.floor(Date.now() / 1000) + 60,
					  jti: crypto.randomUUID() };
				t = jwt.sign(a,
							 context.jwtConf.secret ? context.jwtConf.secret : context.jwtConf.secretKey,
							 { algorithm: context.jwtConf.algorithm } );
				if (! t) {
					throw new Error('Unusable secret key');
				}
				b = jwt.verify(t,
							   context.jwtConf.secret ? context.jwtConf.secret : context.jwtConf.publicKey,
							   { algorithms: [ context.jwtConf.algorithm ] } );
				if (! (b && (b.iss === a.iss) && (b.jti === a.jti))) {
					throw new Error('Unusable public key');
				}
				context.jtRevocation.set(a.jti, a.exp);
			})(null, null, null);
		} catch (e) {
			jwt.secret = undefined;
			context.jwtConf.secretKey = undefined;
			context.jwtConf.publicKey = undefined;
			context.jwtConf.algorithm = undefined;
		}
		if (! context.jwtConf.algorithm) {
			console.error('Invalid symmetric secret or public key pair');
			process.error(1);
		}
		if (! readStaticContent()) {
			console.log('Unable to read static content');
			process.error(1);
		}
		return (Promise.resolve()
				.then(function() {
					fs.watch(opt.value('users-file'), updateUsers);
					return userFileRead(opt.value('users-file'));
				})
				.then(function(ret) {
					context.users = ret;
				})
				.then(function() {
					if (opt.value('clients-file')) {
						fs.watch(opt.value('clients-file'), updateClients);
						return clientFileRead(opt.value('clients-file'));
					}
					return null;
				})
				.then(function(ret) {
					context.clients = ret;
				})
				.then(function(ret) {
					debug(context);
				})
				.then(function() {
					context.server = http.createServer(requestCb);
					context.server.on('error', function(e) {
						fatal('Unable to start HTTP server');
					});
					context.server.headersTimeout = 2000;
					context.server.listen(opt.value('listen-port'), opt.value('listen-address'));
				})
				.then(function() {
					context.interval = setInterval(intervalCb, 10000);
				})
				.then(function() {
					log(`OAUTH2 server is running in ${opt.value('listen-address')}:${opt.value('listen-port')}`);
				})
				.catch(function(e) {
					fatal(e);
				}));
	})();

	function intervalCb() {
		let now = Math.floor(Date.now() / 1000);
		context.jtRevocation.forEach(function(exp, jti, map) {
			if ((exp + 900)  < now) {
				map.delete(jti);
			}
		});
	}

	function updateUsers(ev, fn) {
		(async function() {
			try {
				delay(1000);
				debug('Updating users');
				let u = await userFileRead(opt.value('users-file'));
				for (let n of context.users.keys()) {
					if (! u.has(n)) {
						context.jtLogout.set(n, Math.floor(Date.now() / 1000));
					}
				}
				context.users = u;
			} catch (e) {
				fatal(e);
			}
		})();
	}

	function updateClients(ev, fn) {
		if (! opt.value('clients-file')) {
			return;
		}
		(async function() {
			try {
				delay(1000);
				debug('Updating clients');
				let u = await userFileRead(opt.value('users-file'));
				for (let n of context.users.keys()) {
					if (! u.has(n)) {
						context.jtLogout.set(n, Math.floor(Date.now() / 1000));
					}
				}
				context.users = u;
			} catch (e) {
				fatal(e);
			}
		})();
	}

	function validateUserAuth(auth) {
		if (! (context?.users &&
			   ((typeof(auth?.user) === 'string')) &&
			   ((typeof(auth?.password) === 'string')))) {
			debug('Malformed auth data');
			return undefined;
		}
		let u = context.users.get(auth.user) ?? context.users.get('*');
		if (! u) {
			debug('Unknown user');
			return undefined;
		}
		if (u && ((! u.password) || (auth.password === u.password))) {
			debug(`Auth ok for ${auth.user}`);
			return {
				user: auth.user,
				user_password_set: ((u.password && u.password.length) ? true : false),
				scope: u.scope,
				authorities: u.authorities,
				ttl: u.ttl
			};
		}
		debug('Invalid auth data');
		return undefined;
	}

	function parseBasicAuth(s) {
		let m, b;
		if ((typeof(s) !== 'string') ||
			(! (m = s.match(/^\s*Basic\s+([0-9A-Za-z\+\\]+={0,2})\s*/)))) {
			return undefined;
		}
		if (! Buffer.isBuffer(b = Buffer.from(m[1], 'base64'))) {
			return undefined;
		}
		if (! (m = b.toString('utf8').match(/^([^:]*):(.*)$/))) {
			return undefined;
		}
		return { user: m[1], password: m[2] };
	}

	function noCache(res) {
		res.setHeader('Pragma', 'no-cache');
		res.setHeader('Cache-Control',
					  'no-store, no-cache, must-revalidate, pre-check=0, post-check=0, max-age=0');
		res.setHeader('Expires', 'Thu, 01 Jan 1970 00:00:00 GMT');
	}

	function error(res, code, text, RFC6749EC) {
		if (RFC6749EC) {
			// RFC6749 wants these errors to be code 400 except in case of 401
			res.writeHead((code != 401) ? 400 : 401,
						  { 'Content-Type': 'application/json' });
			res.write(JSON.stringify( { error: RFC6749EC,
										error_description: (text ?
															(text +
															 ' (HTTP code ' +
															 code.toString() +
															 ')') :
															('HTTP code ' +
															 code.toString())) },
									  null, 2));

			res.write("\n");
		} else {
			res.writeHead(code, { 'Content-Type': 'text/plain' });
			res.write(text);
			res.write("\n");
		}
		res.end();
	}

	function createToken(user) {
		let now = Math.floor(Date.now() / 1000);
		let data = {
			iss: context.jwtConf.issuer,
			kid: null,
			iat: now,
			exp: now + (user.ttl ?? context.jwtConf.defaultTTL),
			scope: Array.from(user.scope ?? []),
			authorities: Array.from(user.authorities ?? []),
			jti: crypto.randomUUID(),
			client_id: user.user
		};
		if (data.scope.length < 1) {
			delete data.scope;
		}
		if (data.authorities.length < 1) {
			delete data.authorities;
		}
		if (context.jwtConf.keyId) {
			data.kid = context.jwtConf.keyId;
		} else {
			delete data.kid;
		}
		return { token: jwt.sign(data,
								 (context.jwtConf.secret ?
								  context.jwtConf.secret :
								  context.jwtConf.secretKey),
								 { algorithm: context.jwtConf.algorithm }),
				 jti: data.jti,
				 exp: data.exp,
				 expires_in: data.exp - now };
	}

	function validateToken(token) {
		let now = Math.floor(Date.now() / 1000);
		let data;
		try {
			data = jwt.verify(token,
							  (context.jwtConf.secret ?
							   context.jwtConf.secret :
							   context.jwtConf.publicKey),
							  { algorithms: [ context.jwtConf.algorithm ] } );
		} catch (e) {
			data = undefined;
		}
		if (! (data &&
			   (typeof(data) === 'object') &&
			   data.iat && (typeof(data.iat) === 'number') && (data.iat <= now) &&
			   data.exp && (typeof(data.exp) === 'number') && (data.exp >= now) &&
			   (data.iss === context.jwtConf.issuer) &&
			   data.jti && (typeof(data.jti) === 'string') && (! context.jtRevocation.has(data.jti)) &&
			   data.client_id && (typeof(data.client_id) === 'string') &&
			   ((! context.jtLogout.has(data.client_id)) ||
				(data.iat > context.jtLogout.get(data.client_id))))) {
			return undefined;
		}
		if (typeof(data.scope) === 'string') {
			data.scope = new Set([ data.scope ]);
		} else if (data.scope === undefined) {
			data.scope = new Set();
		} else if (isArrayOfStrings(data.scope)) {
			data.scope = new Set(data.scope);
		} else {
			return undefined;
		}
		return data;
	}

	function handle(r)
	{
		let res = r.res, rd = {}, token, user;
		delete r.res;
		noCache(res);
		r.auth = r.headers.authorization ? parseBasicAuth(r.headers.authorization) : undefined;
		debug('url:', r.url)
		debug('method:', r.method)
		debug('params:', r.params)
		debug('auth:', r.auth)
		switch (r.url) {
		case '/token':
			r.user = validateUserAuth(r.auth);
			if (! r.user) {
				res.setHeader('WWW-Authenticate', 'Basic realm="OAUTH2/' + context.jwtConf.issuer + '"');
				error(res, 401,
					  'Valid authentication is required to access this resource.',
					  'invalid_client');
				return;
			}
			if (r.params.grant_type !== 'client_credentials') {
				error(res, 400,
					  'Invalid grant_type (only client_credentials allowed).',
					  'unsupported_grant_type');
				return;
			}
			if (r.params.scope) {
				if ((r.params.scope === '*') ||
					(! (r.user.scope.has(r.params.scope) ||
						r.user.scope.has('*')))) {
					error(res, 403,
						  'Scope invalid, unknown, malformed or exceeds what can be granted.',
						  'invalid_scope');
					return;
				}
				r.user.scope = new Set([ r.params.scope ]);
			} else {
				r.user.scope = new Set();
			}
			token = createToken(r.user);
			rd = {
				access_token: token.token,
				token_type: 'bearer',
				expires_in: token.exp - Math.ceil(Date.now() / 1000),
				scope: Array.from(r.user.scope),
				authorities: r.user.authorities,
				jti: token.jti
			};
			break;
		case '/check_token':
			if (! (r.params.token &&
				   (typeof(r.params.token) === 'string') &&
				   r.params.token.length)) {
				error(res, 400, 'Parameter token must exist and be a string.');
				return;
			}
			if (token = validateToken(r.params.token)) {
				rd = {
					active: true
				};
				rd = Object.assign(rd, token);
			} else {
				rd = { active: false };
			}
			break;
		case '/revoke_all':
			r.user = validateUserAuth(r.auth);
			if (! r.user) {
				res.setHeader('WWW-Authenticate', 'Basic realm="oauth2/client"');
				error(res, 401,
					  'Valid authentication is required to access this resource.',
					  'invalid_client');
				return;
			}
			if (! (r.params.client_id &&
				   (typeof(r.params.client_id) === 'string') &&
				   r.params.client_id.length)) {
				error(res, 400,
					  'Parameter client_id must exist and be a string.',
					  'invalid_request');
				return;
			}
			if (r.params.client_id !== r.user.user) {
				error(res, 403,
					  'Authenticated user does not match to the client_id.',
					  'invalid_client');
				return;
			}
			if (! r.user.user_password_set) {
				error(res, 403,
					  'Users with no password set, can revoke only individual tokens.',
					  'invalid_client');
				return;
			}
			context.jtLogout.set(r.params.client_id, Math.floor(Date.now() / 1000));
			rd = {
				active: false,
				client_id: r.params.client_id
			};
			break;
		case '/revoke_token':
			r.user = validateUserAuth(r.auth);
			if (! r.user) {
				res.setHeader('WWW-Authenticate', 'Basic realm="oauth2/client"');
				error(res, 401,
					  'Valid authentication is required to access this resource.',
					  'invalid_client');
				return;
			}
			if (! (r.params.token &&
				   (typeof(r.params.token) === 'string') &&
				   r.params.token.length)) {
				error(res, 400,
					  'Parameter token must exist and be a string.',
					  'invalid_request');
				return;
			}
			if (! (token = validateToken(r.params.token))) {
				error(res, 403,
					  'Token is invalid, expired, or revoked.',
					  'invalid_grant');
				return;
			}
			if (token.client_id !== r.user.user) {
				error(res, 403,
					  'Token is was issued to another client',
					  'invalid_grant');
				return;
			}
			context.jtRevocation.set(token.jti, token.exp);
			rd = {
				active: false,
				jti: token.jti
			};
			break;
		case '/keys':
			if (! ['GET'].includes(r.method)) {
				error(res, 405, 'Only GET is allowed.', 'invalid_request');
				return;
			}
			rd = { keys: [] };
			if (context.jwtConf.keyId && context.jwtConf.publicKeyJwk) {
				rd.keys.push( { alg: context.jwtConf.algorithm,
								kty: context.jwtConf.publicKeyJwk.kty,
								use: 'sig',
								kid: context.jwtConf.keyId,
								n: context.jwtConf.publicKeyJwk.n,
								e: context.jwtConf.publicKeyJwk.e
							  } );
			}
			break;
		case '/authorize':
			{
				if (! context.clients) {
					error(res, 404, 'Resource not found.');
					return;
				}
				let content = context.staticContent.get('authorize')
				if (! content) {
					error(res, 404, 'Resource not found.');
					return;
				}
				if (! (r.params.response_type === 'code')) {
					error(res, 400, 'Invalid request parameter (response_type)');
					return;
				}
				if (! (r.params.client_id && (typeof(r.params.client_id) === 'string'))) {
					error(res, 400, 'Invalid request parameter (client_id)');
					return;
				}
				if (! (r.params.redirect_uri &&
					   (typeof(r.params.redirect_uri) === 'string') &&
					   URL.canParse(r.params.redirect_uri))) {
					error(res, 400, 'Invalid request parameter (redirect_uri)');
					return;
				}
				if (! (typeof(r.params.scope) === 'string')) {
					error(res, 400, 'Invalid request parameter (scope)');
					return;
				}
				if (! (r.params.state && (typeof(r.params.state) === 'string'))) {
					error(res, 400, 'Invalid request parameter (state)');
					return;
				}
				if (((r.params.username && (typeof(r.params.username) === 'string')) &&
					 (r.params.password && (typeof(r.params.password) === 'string')))) {
					let client = context.clients.get(r.params.client_id);
					if (! client) {
						error(res, 403, 'Invalid client');
						return;
					}
					if (client.redirect_uri !== r.params.redirect_uri) {
						error(res, 403, 'Invalid redirect for client');
						return;
					}
					let auth = { user: r.params.username, password: r.params.password };
					let user = validateUserAuth(auth);
					if (user) {
						if (r.params.scope) {
							if ((r.params.scope !== '*') && ((user.scope.has(r.params.scope) || user.scope.has('*')))) {
								user.scope = new Set([ r.params.scope ]);
							} else {
								user.scope = undefined;
							}
						} else {
							user.scope = new Set();
						}
						if (user.scope) {
							let token = createToken(user);
							let redirect = (r.params.redirect_uri +
											'?' +
											qs.stringify({ access_token: token.token,
														   token_type: 'Bearer',
														   expires_in: token.expires_in,
														   state: r.params.state }));
							res.writeHead(302, { 'Content-Type': 'text/html; charset=utf-8',
												 'Location': redirect,
												 'Connection': 'close' });
							res.end();
							return;
						}
					}
				}
				let subs = new Map([ [ 'username', r.params.username ?? null ],
									 [ 'client_id', r.params.client_id ?? null ],
									 [ 'redirect_uri', r.params.redirect_uri ?? null ],
									 [ 'response_type', r.params.response_type ?? null ],
									 [ 'scope', r.params.scope ?? null ],
									 [ 'state', r.params.state ?? null ] ]);
				content = template(content, subs);
				res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
				res.write(content);
				res.end();
				return;
			}
		default:
			error(res, 404, 'Resource not found.');
			return;
		}
		res.writeHead(200, { 'Content-Type': 'application/json' });
		res.write(JSON.stringify(rd, null, 2));
		res.end();
	}

	function requestCb(req, res) {
		let completed = false, body = Buffer.alloc(0), r = {}, timeout;
		function dataCb(data) {
			if (completed) {
				return;
			}
			body = Buffer.concat( [ body, data ] );
		}
		function endCb() {
			if (completed) {
				return;
			}
			completed = true;
			if (timeout) {
				clearTimeout(timeout);
				timeout = undefined;
			}
			switch (req.method) {
			case 'POST':
				if (req.url.match(/\?/)) {
					error(res, 400, 'URL for POST must not contain query parameters.');
					return;
				}
				r.url = req.url;
				r.method = req.method;
				switch (req.headers['content-type']) {
				case 'application/x-www-form-urlencoded':
				case 'application/www-form-urlencoded':
					if (! (r.params = qs.parse(body.toString('utf8')))) {
						error(res, 400, 'Unable to parse query parameters.');
						return;
					}
					break;
				case 'application/json':
				case 'application/json;charset=utf-8':
				case 'application/json;charset=UTF-8':
				case 'application/json; charset=utf-8':
				case 'application/json; charset=UTF-8':
					try {
						r.params = JSON.parse(body.toString('utf8'));
					} catch(e) {
						r.params = undefined;
					}
					if (! (r.params && (typeof(r.params) === 'object'))) {
						error(res, 400, 'Unable to parse JSON query parameters.');
						return;
					}
					break;
				case 'multipart/form-data':
					// We know this, but only wankers would use it here.
					// RFC6749 anyways says that application/x-www-form-urlencoded
					// is the "correct" way to go.
				default:
					error(res, 400, 'POST body must be in JSON or www-form-urlencoded format.');
					return;
				}
				break;
			case 'GET':
				if (body.length > 0) {
					error(res, 400, 'Empty body required for GET requests.');
					return;
				}
				let m;
				if (m = req.url.match(/^([^\?]*)\?(.*)$/)) {
					r.url = m[1];
					if (! (r.params = qs.parse(m[2].toString('utf8')))) {
						error(res, 400, 'Unable to parse query parameters.');
						return;
					}
				} else {
					r.url = req.url;
					r.params = {};
				}
				r.method = req.method;
				break;
			default:
				error(res, 405, 'Only GET and POST are allowed.');
				return;
			}
			r.headers = req.headers;
			r.res = res;
			handle(r);
		}
		function errorCb() {
			if (completed) {
				return;
			}
			completed = true;
			if (timeout) {
				clearTimeout(timeout);
				timeout = undefined;
			}
			error(res, 400, 'Error occured while reading the request data.');
		}
		function timeoutCb() {
			if (completed) {
				return;
			}
			timeout = undefined;
			completed = true;
			error(res, 408, 'Timeout occured wile reading the request data.');
		}
		timeout = setTimeout(timeoutCb, 2000);
		req.on('data', dataCb);
		req.on('end', endCb);
		req.on('error', errorCb);
	}

};
