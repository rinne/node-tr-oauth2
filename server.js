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
	const validators = require('./validators');

	/*
	  If tokens must remain valid over restart, define secret as a random
	  string and keep it secret. Otherwise a random secret is created
	  automatically every time the program starts. Alternatively, use
	  a keypair, which in most cases is the correct answer anyways.
	*/

	var context = {
		debug: false,
		users: new Map(),
		emails: new Map(),
		clients: null,
		revocations: new Map(),
		logouts: new Map(),
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
					   { longName: 'allow-empty-password',
						 description: 'Allow empty password.',
						 environment: 'TR_OAUTH2_OPT_ALLOW_EMPTY_PASSWORD' },
					   { longName: 'allow-empty-scope',
						 description: 'Allow empty scope.',
						 environment: 'TR_OAUTH2_OPT_ALLOW_EMPTY_SCOPE' },
					   { longName: 'token-ttl',
						 description: 'Default validity time for tokens in seconds.',
						 hasArg: true,
						 defaultValue: '3600',
						 environment: 'TR_OAUTH2_OPT_TOKEN_TTL',
						 optArgCb: ou.integerWithLimitsCbFactory(1, 999999999999) },
					   { longName: 'token-issuer',
						 description: 'Issuer name to be included into tokens.',
						 hasArg: true,
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
						 optArgCb: ou.existingFileNameCb,
						 required: true },
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
										   debug('emails:', context.users);
										   debug('clients:', context.clients);
										   debug('revocation:', context.revocations);
										   debug('logout:', context.logouts); });
	}

	(function() {

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
			// Try to create a dummy token to test that keys are ok.
			let user = {
				'#': 1,
				username: crypto.randomUUID(),
				email: crypto.randomUUID() + '@' + crypto.randomUUID() + '.com',
				password: crypto.randomUUID(),
				scope: new Set([crypto.randomUUID()]),
				totp: null
			};
			let client = {
				client_id: crypto.randomUUID(),
				client_secret: null,
				ttl: 30,
				redirect_uri: 'none://none'
			};
			let _users = context.users;
			let _clients = context.clients;
			context.users = new Map();
			context.clients = new Map();
			context.users.set(user.username, user);
			context.clients.set(client.client_id, client);
			let created = createToken(user, client);
			let decoded = validateToken(created.token);
			revokeToken(decoded.jti, decoded.exp);
			context.users = _users;
			context.clients = _clients;
		} catch (e) {
			console.log(e);
			jwt.secret = undefined;
			context.jwtConf.secretKey = undefined;
			context.jwtConf.publicKey = undefined;
			context.jwtConf.algorithm = undefined;
		}
		if (! context.jwtConf.algorithm) {
			console.error('Invalid symmetric secret or public key pair');
			process.exit(1);
		}
		if (! readStaticContent()) {
			console.log('Unable to read static content');
			process.exit(1);
		}
		return (Promise.resolve()
				.then(function() {
					fs.watch(opt.value('users-file'), updateUsers);
					return userFileRead(opt.value('users-file'));
				})
				.then(function(ret) {
					context.users = ret[0];
					context.emails = ret[1];
				})
				.then(function() {
					fs.watch(opt.value('clients-file'), updateClients);
					return clientFileRead(opt.value('clients-file'));
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
					context.interval = setInterval(intervalCb, 900000);
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
		debug('Checking revocations');
		for (let [ jti, exp ] of context.revocations) {
			if ((exp + 900)  < now) {
				debug(`Revoked token ${jti} already expired`);
				context.revocations.delete(jti);
			}
		}
	}

	function updateUsers(ev, fn) {
		(async function() {
			try {
				delay(1000);
				debug('Updating users');
				let r = await userFileRead(opt.value('users-file'));
/*
				// Handle revocations of changed records here XXXXX
				for (let n of context.users.keys()) {
					if (! u.has(n)) {
						context.jtLogout.set(n, Math.floor(Date.now() / 1000));
					}
				}
*/
				context.users = r[0];
				context.emails = r[1];
			} catch (e) {
				fatal(e);
			}
		})();
	}

	function updateClients(ev, fn) {
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

	function validateUserAuth(auth, client) {
		if (! (context?.users &&
			   ((typeof(auth?.user) === 'string')) &&
			   ((typeof(auth?.password) === 'string')))) {
			debug('Malformed auth data');
			return undefined;
		}
		const u = context.users.get(auth.user) ?? context.users.get(context.emails.get(auth.user));
		if (u && (((! u.password) && opt.value('allow-empty-password')) || (u.password && (auth.password === u.password)))) {
			debug(`Auth ok for login ${auth.user} => user ${u.username}`);
			let r = Object.assign({}, u);
			delete r['#'];
			return r;
		}
		debug('Invalid auth data');
		return undefined;
	}

	function parseBasicAuth(s) {
		try {
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
		} catch (e) {
			console.error(e);
			return undefined;
		}
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

	function isRevoked(d) {
		now = Math.floor(Date.now() / 1000);
		if (! ((d?.sub && (typeof(d.sub) === 'string')) &&
			   (d?.jti && (typeof(d.jti) === 'string')) &&
			   Number.isSafeInteger(d?.iat))) {
			debug('Declaring token revoked because bad sub, jti, or iat');
			return true;
		}
		if (context.revocations.has(d.jti)) {
			debug(`Token ${d.jti} is revoked`);
			return true;
		}
		let logout = context.logout.get(d.sub);
		if (logout && (logout >= d.iat)) {
			debug(`Token ${d.jti} is revoked because user ${d.sub} was logged out at ${logout} and token issued at ${d.iat}`);
			return true;
		}
		return false;
	}

	function revokeToken(jti, exp) {
		if (jti) {
			context.revocations.set(jti, exp ?? null);
			return true;
		}
		return false;
	}

	function logoutUset(username) {
		if (username) {
			context.logouts.set(username, Math.floor(Date.now() / 1000));
			return true;
		}
		return false;
	}

	function createToken(user, client, extraClaims) {
		debug('createToken', user, client, extraClaims);
		let now = Math.floor(Date.now() / 1000);
		let data = {
			sub: user.username,
			email: null,
			iss: null,
			kid: null,
			iat: now,
			exp: now + (user.ttl ?? client.ttl ?? opt.value('token-ttl')),
			scope: Array.from(user.scope),
			jti: crypto.randomUUID(),
			client_id: client.client_id
		};
		if (extraClaims) {
			for (let c of Object.keys(data)) {
				if (c in extraClaims) {
					debug(`Extra claims can't shadow basic claim ${c}`);
					return undefined;
				}
			}
			Object.assign(data, extraClaims);
		}
		if (user.email) {
			data.email = user.email;
		} else {
			let email = validators.validateEmail(user.username);
			if (email) {
				data.email = email;
			} else {
				delete data.email;
			}
		}
		if (data.scope.length < 1) {
			delete data.scope;
		}
		if (opt.value('token-issuer')) {
			data.iss = opt.value('token-issuer');
		} else {
			delete data.iss;
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
		debug('validateToken:', token);
		let now = Math.floor(Date.now() / 1000);
		let data;
		try {
			data = jwt.verify(token,
							  (context.jwtConf.secret ?
							   context.jwtConf.secret :
							   context.jwtConf.publicKey),
							  { algorithms: [ context.jwtConf.algorithm ] } );
		} catch (e) {
			console.log(e);
			debug('Invalid token');
			return undefined;
		}
		if (! ((data?.sub && (typeof(data.sub) === 'string')) &&
			   (data?.jti && (typeof(data.jti) === 'string')) &&
			   (data?.client_id && (typeof(data.client_id) === 'string')) &&
			   Number.isSafeInteger(data?.iat) &&
			   Number.isSafeInteger(data?.exp) &&
			   ((data?.email === undefined) || (data?.email && (typeof(data.email) === 'string'))) &&
			   ((data?.iss === undefined) || (data?.iss && (typeof(data.iss) === 'string'))) &&
			   ((data?.scope === undefined) || isArrayOfStrings(data.scope)) &&
			   ((data?.rjti === undefined) || (data?.rjti && (typeof(data.rjti) === 'string'))) &&
			   ((data?.rgen === undefined) || (Number.isSafeInteger(data.rgen) && (data.rgen >= 0))))) {
			debug('Invalid token payload');
			return undefined;
		}
		let client = context.clients.get(data.client_id);
		if (! client) {
			debug(`Token client ${data.client_id} is no longer valid`);
			return undefined;
		}
		let user = context.users.get(data.sub);
		if (! user) {
			debug(`Token user ${data.user} is no longer valid`);
			return undefined;
		}
		if ((data.iss || opt.value('token-issuer')) && (data.iss !== opt.value('token-issuer'))) {
			debug('Token issuer mismatch');
			return undefined;
		}
		if (data.exp < now) {
			debug('Token expired');
			return undefined;
		}
		if ((data.iat - 60) > now) {
			debug('Token issued in the future -> revoking it');
			revokeToken(data.jti, data.exp);
			return undefined;
		}
		data.scope = data.scope ? new Set(data.scope) : new Set();
		for (let s of data.scope) {
			if (! user.scope.has(s)) {
				debug(`User ${data.user} is no longer has token scope ${s}`);
				return undefined;
			}
		}
		return data;
	}

	function handle(r)
	{
		let res = r.res, rd = {}, token, user;
		delete r.res;
		noCache(res);
		let client = undefined;
		let clientAuth = false;
		{
			let client_id, client_secret;
			if (r.headers.authorization) {
				let ba = parseBasicAuth(r.headers.authorization);
				if (ba) {
					client_id = ba.user;
					client_secret = ba.password;
				}
			}
			if (r.params.client_id) {
				client_id = r.params.client_id;
			}
			if (r.params.client_secret) {
				client_secret = r.params.client_secret;
			}
			if (! (client_id && (typeof(client_id) === 'string') && context.clients.has(client_id))) {
				client_id = undefined;
			}
			if (client_id) {
				client = context.clients.get(client_id);
				if (client && ((! client.client_secret) || (client_secret === client.client_secret))) {
					clientAuth = true;
				}
			}
		}
		debug('url:', r.url)
		debug('method:', r.method)
		debug('params:', r.params)
		debug('client:', client)
		debug('clientAuth:', clientAuth)

		switch (r.url) {
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
		case '/token':
			{
				if (! client) {
					error(res, 400, 'Invalid client');
					return;
				}
				if (! [ 'password', 'refresh_token' ].includes(r.params.grant_type)) {
					error(res, 400, 'Invalid grant type');
					return;
				}
				if (! (typeof(r.params.scope) === 'string')) {
					error(res, 400, 'Invalid scope');
					return;
				}
				let user;
				let extraClaims = {};
				switch (r.params.grant_type) {
				case 'password':
					if (! clientAuth) {
						error(res, 400, 'Invalid client');
						return;
					}
					if (! ((r.params.username && (typeof(r.params.username) === 'string')) &&
						   (r.params.password && (typeof(r.params.password) === 'string')))) {
						error(res, 400, 'Invalid authentication data');
						return;
					}
					let auth = { user: r.params.username, password: r.params.password };
					user = validateUserAuth(auth, client);
					break;
				case 'refresh_token':
					if (! (r.params.refresh_token && (typeof(r.params.refresh_token) === 'string'))) {
						error(res, 400, 'Invalid authentication data');
						return;
					}
					let tokenData = validateToken(r.params.refresh_token);
					if (! tokenData) {
						error(res, 400, 'Invalid authentication data');
						return;
					}
					user = context.users.get(tokenData.sub);
					// We will override the user token with the one
					// from the token (which is a subset of the user
					// scope). Scope can only be the same or reduced
					// from the token when refreshing. In order to
					// expand the scope, a new token must be created
					// using password grant.
					user.scope = tokenData.scope;
					// We'll track the token ancestry.
					debug('ec1', extraClaims);
					extraClaims.rjti = tokenData.rjti ?? tokenData.jti;
					extraClaims.rgen = tokenData.rgen ? tokenData.rgen + 1 : 1;
					debug('ec1', extraClaims);
					break;
				default:
					error(res, 400, 'Internal error');
					return;
				}
				if (! user) {
					error(res, 400, 'Invalid authentication data');
					return;
				}
				if (r.params.scope) {
					let scope = new Set();
					for (let s of new Set(r.params.scope.split(/[\s,]+/).filter(s=>((!!s) && (s!==','))).sort())) {
						if (! (user.scope.has(s) || user.scope.has('*'))) {
							debug(`Requested scope ${s} not allowed for ${user.username}`);
							scope = undefined;
							break;
						}
						scope.add(s);
					}
					user.scope = scope;
				} else if (opt.value('allow-empty-scope')) {
					debug(`Allowing empty scope for ${user.username}`);
					user.scope = new Set();
				} else {
					debug(`Not allowing empty scope for ${user.username}`);
					user.scope =  undefined;
				}
				if (! user.scope) {
					error(res, 400, 'Invalid authentication data');
					return;
				}
				debug(`User ${user.username} authenticated. Creating token.`);
				let token = createToken(user, client, extraClaims);
				if (! token) {
					debug(`Token creation failed.`);
					error(res, 500, 'Internal error');
					return;
				}
				rd = {
					access_token: token.token,
					token_type: 'Bearer',
					expires_in: token.exp - Math.floor(Date.now() / 1000),
					scope: Array.from(user.scope).join(' ')
				};
				break;
			}
		case '/check_token':
			{
				if (! clientAuth) {
					error(res, 400, 'Invalid client');
					return;
				}
				if (! (r.params.token && (typeof(r.params.token) === 'string'))) {
					error(res, 400, 'Parameter token must exist and be a string.');
					return;
				}
				if (token = validateToken(r.params.token)) {
					rd = {
						active: true
					};
					rd = Object.assign(rd, token);
					if (rd.scope) {
						rd.scope = Array.from(rd.scope);
					}
				} else {
					rd = { active: false };
				}
				break;
			}
		case '/authorize':
			{
				if (! client) {
					error(res, 400, 'Invalid client');
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
					if (client.redirect_uri !== r.params.redirect_uri) {
						error(res, 403, 'Invalid redirect for client');
						return;
					}
					let auth = { user: r.params.username, password: r.params.password };
					let user = validateUserAuth(auth, client);
					if (user) {
						console.log(user);
						if (r.params.scope) {
							let scope = new Set();
							for (let s of new Set(r.params.scope.split(/[\s,]+/).filter(s=>((!!s) && (s!==','))).sort())) {
								if (! (user.scope.has(s) || user.scope.has('*'))) {
									debug(`Requested scope ${s} not allowed for ${user.username}`);
									scope = undefined;
									break;
								}
								scope.add(s);
							}
							user.scope = scope;
						} else if (opt.value('allow-empty-scope')) {
							debug(`Allowing empty scope for ${user.username}`);
							user.scope = new Set();
						} else {
							debug(`Not allowing empty scope for ${user.username}`);
							user.scope =  undefined;
						}
						if (user.scope) {
							debug(`User ${user.username} authenticated. Creating token.`);
							let token = createToken(user, client);
							if (token) {
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
							} else {
								debug(`Token creation failed.`);
							}
						}
					} else {
						debug(`Authentication fails for ${auth?.user}`);
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
