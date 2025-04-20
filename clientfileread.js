'use strict';

const csvRead = require('./csvread');

const v = require('./validators');

async function clientFileRead(filename) {
	let spec = {
		'#': '#linenumber',
		key: 'client_id',
		fields: {
			'client_id': { validator: v.validateRegExpFactory(/^\S{1,64}$/) },
			'client_secret': { validator: v.validateRegExpFactory({ pattern: /^.{1,128}$/,
																	emptyValue: null }),
							   optional: true },
			'ttl': { validator: v.validateIntFactory({ min: 1,
													   max: 2147483647,
													   emptyValue: null }),
					 optional: true },
			'redirect_uri': { validator: v.validateUri }
		}
	};
	let r = await csvRead(filename, spec);
	console.log(r);
	return r;
}

module.exports = clientFileRead;
