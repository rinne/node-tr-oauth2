'use strict';

const u = require('url');
const qs = require('querystring')
const call = require('./call.js');

function revoke(url, token, user, password) {
	return (call(url, { token: token } , user, password)
			.then(function(ret) {
				if (ret.active !== false) {
					throw new Error('Invalid token');
				}
				return ret;
			})
			.catch(function(e) {
				throw e;
			}));
}

module.exports = revoke;
