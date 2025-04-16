'use strict';

const csvRead = require('./csvread');

const v = require('./validators');

let spec = {
	key: 'client_id',
	fields: {
		'client_id': { validator: v.validateRegExpFactory(/^\S{1,64}$/) },
		'client_secret': { validator: v.validateRegExpFactory({ pattern: /^.{1,128}$/, emptyValue: null }) },
		'redirect_uri': { validator: v.validateUri }
	}
};

async function clientFileRead(filename) {
	let r = await csvRead(filename, spec);
	return r;
}

module.exports = clientFileRead;
