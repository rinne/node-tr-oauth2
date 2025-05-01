'use strict';

const csvRead = require('./csvread');

const v = require('./validators');

async function clientFileRead(filename) {
	let spec = {
		'#': '#linenumber',
		key: 'client_id',
		fields: {
			'client_id': {
				validator: v.validateRegExpFactory(/^\S{1,64}$/) },
			'client_secret': {
				validator: v.validateRegExpFactory({ pattern: /^.{1,128}$/, emptyValue: null }),
				optional: true },
			'ttl': {
				validator: v.validateIntFactory({ min: 1, max: 2147483647, emptyValue: null }),
				optional: true },
			'redirect_uri': {
				validator: v.validateUri },
			'allow_anonymous': {
				validator: v.validateBool,
				emptyValue: false,
				optional: true },
			'anonymous_scopes': {
				validator: v.validateCslFactory({ validator: v.validateRegExpFactory(/^\S{1,64}$/), separator: /[\s,]+/ } ),
				emptyValue: new Set(),
				optional: true },
			'ext_auth_url': {
				validator: v.validateUri,
				optional: true },
			'ext_auth_secret': {
				validator: v.validateRegExpFactory({ pattern: /^.{1,128}$/, emptyValue: null }),
				optional: true },
			'ext_auth_scopes': {
				validator: v.validateCslFactory({ validator: v.validateRegExpFactory(/^\S{1,64}$/), separator: /[\s,]+/ } ),
				emptyValue: new Set(),
				optional: true }
		}
	};
	let r = await csvRead(filename, spec);
	console.log(r);
	return r;
}

module.exports = clientFileRead;
