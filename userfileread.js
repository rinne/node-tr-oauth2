'use strict';

const csvRead = require('./csvread');

const v = require('./validators');

let spec = {
	key: 'username',
	fields: {
		'username': { validator: v.validateRegExpFactory(/^\S{1,64}$/) },
		'password': { validator: v.validateRegExpFactory({ pattern: /^.{8,128}$/, emptyValue: null }) },
		'ttl': { validator: v.validateIntFactory({ min: 1, max: 2147483647, emptyValue: null } ) },
		'authorities': { validator: v.validateCslFactory({ validator: v.validateRegExpFactory(/^\S{1,64}$/) } ) },
		'scope': { validator: v.validateCslFactory({ validator: v.validateRegExpFactory(/^\S{1,64}$/) }) },
		'email': { validator: v.validateEmail, optional: true }
	}
};

async function userFileRead(filename) {
	let r = await csvRead(filename, spec);
	return r;
}

module.exports = userFileRead;
