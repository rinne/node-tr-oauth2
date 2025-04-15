'use strict';

module.exports = function() {

	const http = require('http');
	const crypto = require('crypto');
	const qs = require('querystring')
	const fs = require('fs');
	const jwt = require('jsonwebtoken');
	const jwk = require('pem-jwk');
	const Optist = require('optist');
	const ou = require('optist/util');

	const userFileRead = require('./userfileread.js');
	userFileRead('users.dat');

	/*
	  If tokens must remain valid over restart, define secret as a random
	  string and keep it secret. Otherwise a random secret is created
	  automatically every time the program starts. Alternatively, use
	  a keypair, which in most cases is the correct answer anyways.
	*/

	var context = {
		users: {},
		jtRevocation: new Map(),
		jtLogout: new Map(),
		jwtConf: {}
	};

	var opt = ((new Optist())
			   .opts([ { longName: 'listen-address',
						 description: 'IP address the server listens to.',
						 hasArg: true,
						 defaultValue: '127.0.0.1',
						 optArgCb: ou.ipv4 },
					   { longName: 'listen-port',
						 description: 'TCP port the server listens to.',
						 hasArg: true,
						 optArgCb: ou.integerWithLimitsCbFactory(1, 65535),
						 required: true },
					   { longName: 'token-ttl',
						 description: 'Default validity time for tokens in seconds.',
						 hasArg: true,
						 defaultValue: '3600',
						 optArgCb: ou.integerWithLimitsCbFactory(1, 999999999999) },
					   { longName: 'token-issuer',
						 description: 'Issuer name to be included into tokens.',
						 hasArg: true,
						 defaultValue: 'anonymous',
						 optArgCb: ou.nonEmptyCb },
					   { longName: 'users-file',
						 description: 'CSV file containing users data.',
						 hasArg: true,
						 optArgCb: ou.existingFileNameCb,
						 required: true },
					   { longName: 'secret-key-file',
						 description: 'Read token signing key from file.',
						 hasArg: true,
						 optArgCb: ou.fileContentsStringCb,
						 conflictsWith: [ 'secret', 'secret-file' ] },
					   { longName: 'public-key-file',
						 description: 'Read token verifying key from file.',
						 hasArg: true,
						 optArgCb: ou.fileContentsStringCb,
						 requiresAlso: 'secret-key-file',
						 conflictsWith: [ 'secret', 'secret-file' ] },
					   { longName: 'secret',
						 description: 'Symmetric secret for token signing.',
						 hasArg: true,
						 optArgCb: ou.nonEmptyCb,
						 conflictsWith: [ 'secret-key-file', 'public-key-file', 'secret-file' ] },
					   { longName: 'secret-file',
						 description: 'Read symmetric secret from file.',
						 hasArg: true,
						 optArgCb: ou.fileContentsStringCb,
						 conflictsWith: [ 'secret-key-file', 'public-key-file', 'secret' ] } ])
			   .help('oauthserver')
			   .parse(undefined, 0, 0));

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
				console.log('Invalid public key pair');
				process.exit(1);
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
			context.jwtConf.secret = crypto.randomBytes(64).toString('base64');
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
			console.log('Invalid symmetric secret or public key pair');
			process.exit(1);
		}
		return (Promise.resolve()
				.then(function() {
					return userFileRead(opt.value('users-file'));
				})
				.then(function(ret) {
					context.users = ret;
				})
				.then(function() {
					context.server = http.createServer(requestCb);
					context.server.on('error', function(e) {
						console.log('Unable to start HTTP server');
						process.exit(1);
					});
					context.server.headersTimeout = 2000;
					context.server.listen(opt.value('listen-port'), opt.value('listen-address'));
				})
				.then(function() {
					context.interval = setInterval(intervalCb, 10000);
				})
				.catch(function(e) {
					console.log(e);
					process.exit(1);
				}));
	})();

	function intervalCb() {
		var now = Math.floor(Date.now() / 1000);
		context.jtRevocation.forEach(function(exp, jti, map) {
			if ((exp + 900)  < now) {
				map.delete(jti);
			}
		});
	}

	function validateUserAuth(auth) {
		var u = ((context.users &&
				  auth &&
				  auth.user &&
				  ((typeof(auth.user) === 'string')) &&
				  auth.password &&
				  ((typeof(auth.password) === 'string'))) ?
				 (context.users[auth.user] ?
				  context.users[auth.user] :
				  (context.users['*'] ?
				   context.users['*'] :
				   undefined)) :
				 undefined);
		if (u && ((! u.password) || (auth.password === u.password))) {
			return {
				user: auth.user,
				user_password_set: ((u.password && u.password.length) ? true : false),
				scope: (u.scope ?
						(Array.isArray(u.scope) ? u.scope : [ u.scope ]) :
						[]),
				authorities: (u.authorities ?
							  (Array.isArray(u.authorities) ?
							   u.authorities :
							   [ u.authorities ]) :
							  []),
				ttl: u.ttl ? u.ttl : null
			};
		}
		return undefined;
	}

	function parseBasicAuth(s) {
		var m, b;
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
		var now = Math.floor(Date.now() / 1000);
		var data = {
			iss: context.jwtConf.issuer,
			kid: null,
			iat: now,
			exp: now + (user.ttl ? user.ttl : context.jwtConf.defaultTTL),
			scope: user.scope,
			authorities: user.authorities,
			jti: crypto.randomUUID(),
			client_id: user.user
		};
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
				 exp: data.exp };
	}

	function validateToken(token) {
		var now = Math.floor(Date.now() / 1000);
		var data;
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
		return data;
	}

	function handle(r)
	{
		var res = r.res, rd = {}, token, user;
		delete r.res;
		noCache(res);
		r.auth = r.headers.authorization ? parseBasicAuth(r.headers.authorization) : undefined;
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
					((r.user.scope.indexOf(r.params.scope) < 0) &&
					 (r.user.scope.indexOf('*') < 0))) {
					error(res, 403,
						  'Scope invalid, unknown, malformed or exceeds what can be granted.',
						  'invalid_scope');
					return;
				}
				r.user.scope = [ r.params.scope ];
			}
			token = createToken(r.user);
			rd = {
				access_token: token.token,
				token_type: 'bearer',
				expires_in: token.exp - Math.ceil(Date.now() / 1000),
				scope: r.user.scope,
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
			if (r.method !== 'GET') {
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
		default:
			error(res, 404, 'Resource not found.');
			return;
		}
		res.writeHead(200, { 'Content-Type': 'application/json' });
		res.write(JSON.stringify(rd, null, 2));
		res.end();
	}

	function requestCb(req, res) {
		var completed = false, body = Buffer.alloc(0), r = {}, timeout;
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
				var m;
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
