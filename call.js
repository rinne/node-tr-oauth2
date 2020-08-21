'use strict';

const u = require('url');
const qs = require('querystring')

function call(url, params, user, password, requestContentType) {
	var http, urlParsed;
	return (Promise.resolve()
			.then(function() {
				urlParsed = u.parse(url);
				switch (urlParsed.protocol) {
				case 'http:':
					http = require('http');
					break;
				case 'https:':
					http = require('https');
					break;
				default:
					throw new Error('Validator called with invalid URL');
				}
				if (! requestContentType) {
					requestContentType = 'application/x-www-form-urlencoded';
				}
				switch (requestContentType) {
				case 'application/x-www-form-urlencoded':
				case 'application/www-form-urlencoded':
				case 'x-www-form-urlencoded':
				case 'www-form-urlencoded':
					requestContentType = 'application/x-www-form-urlencoded';
					break;
				case 'application/json':
				case 'json':
				case 'JSON':
					requestContentType = 'application/json';
					break;
				default:
					throw new Error('Validator called with invalid request content type');
				}
			})
			.then(function() {
				return new Promise(function(resolve, reject) {
					var completed = false;
					var errorCb = function(e) {
						if (completed) {
							return;
						}
						completed = true;
						return reject(e);
					};
					var requestCb = function(res) {
						var body = '';
						if (completed) {
							return;
						}
						if (res.statusCode != 200) {
							console.log(res.statusCode);
							errorCb(new Error('Invalid HTTP status'));
						}
						res.setEncoding('utf8');
						res.on('data', function(data) {
							if (completed) {
								return;
							}
							body += data;
						});
						res.on('end', function() {
							if (completed) {
								return;
							}
							completed = true;
							try {
								body = JSON.parse(body);
							} catch(e) {
								body = undefined;
							}
							if (! (body && (typeof(body) === 'object'))) {
								completed = false;
								errorCb(new Error('Invalid JSON in response body'));
								return;
							}
							return resolve(body);
						});
						res.on('error', errorCb);
					};
					var opt = {
						method: 'GET',
						host: urlParsed.host,
						port: urlParsed.port ? urlParsed.port : undefined,
						path: urlParsed.path,
						auth: ((user && (typeof(user) === 'string') &&
								password && (typeof(user) === 'string')) ?
							   (user + ':' + password) :
							   undefined),
						timeout: 30 * 1000,
					};
					if (params) {
						opt.method = 'POST';
						opt.headers = { 'content-type': requestContentType };
					}
					var req = http.request(opt, requestCb);
					req.on('error', errorCb);
					if (params) {
						switch (requestContentType) {
						case 'application/x-www-form-urlencoded':
							req.write(qs.stringify(params));
							break;
						case 'application/json':
							req.write(JSON.stringify(params));
							break;
						}
					}
					req.end();
				});
			})
			.then(function(ret) {
				return ret;
			})
			.catch(function(e) {
				throw e;
			}));
}

module.exports = call;
