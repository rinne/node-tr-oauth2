'use strict';

function validateUri(s) {
	return (s && (typeof(s) === 'string') && URL.canParse(s)) ? s : undefined;
}

function validateEmail(s) {
    if (! ((typeof(s) === 'string') &&
		   (s.length <= 64) &&
		   (/^.{1,64}@.{1,255}$/.test(s)) &&
		   (/^(\w+([.-]\w+)*)@(\w+(-\w+)*\.){1,5}(\w{2,10})$/.test(s)))) {
	    return undefined;
	}
    return s.toLowerCase();
}

function validateIntFactory(options) {
	options = Object.assign({}, options);
	if ((options.min === undefined) || (options.min === null)) {
		options.min = undefined;
	} else if (! Number.isFinite(options.min)) {
		throw new TypeError('Invalid options.minimum value');
	}
	if ((options.max === undefined) || (options.max === null)) {
		options.max = undefined;
	} else if (! Number.isFinite(options.max)) {
		throw new TypeError('Invalid options.maximum value');
	}
	return function(s) {
		if ((options.emptyValue !== undefined) && (s === '')) {
			return options.emptyValue;
		}
		return _validateInt(s, options.min, options.max);
	}
}

function validateRegExpFactory(options) {
	if (options instanceof RegExp) {
		options = { pattern: options };
	} else {
		options = Object.assign({}, options);
	}
	if (! (options.pattern instanceof RegExp)) {
		throw new TypeError('Pattern not a RegExp');
	}
	options.pattern = new RegExp(options.pattern);
	return function(s) {
		if ((options.emptyValue !== undefined) && (s === '')) {
			return options.emptyValue;
		}
		return _validateRegExp(s, options.pattern);
	}
}

function validateCslFactory(options) {
	options = Object.assign({}, options);
	if ((options.validator === undefined) || (options.validator === null)) {
		options.validator = undefined;
	} else if (typeof(options.validator) !== 'function') {
		throw new TypeError('CSL validator not a function');
	}
	if ((options.separator === undefined) || (options.separator === null)) {
		options.separator = /\s*,\s*/;
	} else if (! ((typeof(options.separator) === 'string') || (options.separator instanceof RegExp))) {
		throw new TypeError('CSL validator not a function');
	}
	return function(s) {
		if ((options.emptyValue !== undefined) && (s === '')) {
			return options.emptyValue;
		}
		s = _validateCsl(s, options.separator);
		if (s === undefined) {
			return undefined;
		}
		let r = new Set();
		for (let i = 0; i < s.length; i++) {
			let ss = s[i];
			if (options.validator) {
				ss = options.validator(s[i]);
			}
			if (ss === undefined) {
				return undefined;
			}
			r.add(ss);
		}
		if ((options.emptyValue !== undefined) && (s.size < 1)) {
			return options.emptyValue;
		}
		return r;
	}
}

// Do not export this.
function _validateCsl(s, sep) {
	if (! (typeof(s) === 'string')) {
		return undefined;
	}
	if (! ((typeof(sep) === 'string') || (sep instanceof RegExp))) {
		return undefined;
	}
	s = s.split(sep).filter(s => (!!s));
	return s;
}

// Do not export this.
function _validateRegExp(s, re) {
	return ((typeof(s) === 'string') && (re.test(s))) ? s : undefined;
}

// Do not export this.
function _validateInt(s, min, max) {
	if ((typeof(s) === 'string') && /^(0|(-?[1-9][0-9]{0,15}))$/.test(s)) {
		s = Number.parseInt(s);
	}
	if (! Number.isSafeInteger(s)) {
		return undefined;
	}
	if (! (((min === undefined) || (min === null) || (Number.isFinite(min))) &&
		   ((max === undefined) || (max === null) || (Number.isFinite(max))))) {
		return undefined;
	}
	if (((typeof(max) === 'number') && (s > max)) || ((typeof(min) === 'number') && (s < min))) {
		return undefined;
	}
	return s;
}

module.exports = { validateUri,
				   validateEmail,
				   validateCslFactory,
				   validateIntFactory,
				   validateRegExpFactory };
