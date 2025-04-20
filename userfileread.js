'use strict';

const csvRead = require('./csvread');
const v = require('./validators');

async function userFileRead(filename) {
	let spec = {
		key: 'username',
		fields: {
			'#': '#linenumber',
			'username': { validator: v.validateRegExpFactory(/^\S{1,64}$/) },
			'password': { validator: v.validateRegExpFactory({ pattern: /^.{8,128}$/ }),
						  emptyValue: null },
			'scope': { validator: v.validateCslFactory({ validator: v.validateRegExpFactory(/^\S{1,64}$/),
														 separator: /[\s,]+/ } ) },
			'email': { validator: v.validateEmail,
					   emptyValue: null,
					   optional: true },
			'totp': { validator: v.validateRegExpFactory({ pattern: /^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{16}$/i }),
					  emptyValue: null,
					  optional: true },
			'ttl': { validator: v.validateIntFactory({ min: 1,
													   max: 2147483647,
													   emptyValue: null }),
					 optional: true }
		}
	};
	let u = await csvRead(filename, spec);
	let m = new Map();
	for (let [k, v] of u) {
		if (v.email) {
			if (m.has(v.email)) {
				throw new Error(`Duplicate email ${v.email} on row ${v['#']}`);
			}
			if (u.has(v.email) && (v.username !== v.email)) {
				throw new Error(`Email ${v.email} on row ${v['#']} already an username of another user on row ${u.get(v.email)['#']}`);
			}
			m.set(v.email, v.username);
		}
	}
	return [ u, m ];
}

module.exports = userFileRead;
