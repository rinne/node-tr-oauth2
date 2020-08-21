'use strict';

const call = require('./call.js');

function validate(url, token, user, password) {
	return (call(url, { token: token } , user, password)
			.then(function(ret) {
				if (ret.active !== true) {
					throw new Error('Invalid token');
				}
				return ret;
			})
			.catch(function(e) {
				throw e;
			}));
}

module.exports = validate;
