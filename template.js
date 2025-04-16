'use strict';

function template(s, subs) {
	if (typeof(s) !== 'string') {
		throw TypeError('Template not a string');
	}
	if ((subs === undefined) || (subs === null)) {
		subs = new Map();
	}
	if (! (subs instanceof Map)) {
		throw TypeError('Substitutions not a map');
	}
	return s.replace(/\{\{[a-zA-Z]([a-zA-Z0-9_]*[a-zA-Z])?\}\}/g, function(m) {
		let n = m.slice(2, -2);
		let r = subs.get(n);
		if ((r === undefined) || (r === null)) {
			r = '';
		} else if (typeof(r) === 'number') {
			r = r.toString();
		} else if (typeof(r) === 'boolean') {
			r = r ? 'true' : 'false';
		} else if (typeof(r) !== 'string') {
			console.warn(`ambiguous value type for substitution ${n}`);
			r = '';
		}
		return r;
	});
}

module.exports = template;
