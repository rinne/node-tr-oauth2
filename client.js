'use strict';

const u = require('url');
const call = require('./call.js');

var DOC = function(url, urlParams, user, password) {
	if (! (this instanceof DOC)) {
		throw new Error('DOC constructor called without new');
	}
	if (! ((typeof(url) === 'string') &&
		   (typeof(user) === 'string') &&
		   (typeof(password) === 'string'))) {
		throw new Error('DOC constructor called with bad parameters');
	}
	this.url = url;
	try {
		this.urlParsed = u.parse(this.url);
	} catch(e) {
		this.urlParsed = undefined;
	}
	if (! this.urlParsed) {
		throw new Error('DOC constructor called with invalid URL');
	}
	switch (this.urlParsed.protocol) {
	case 'http:':
		break;
	case 'https:':
		break;
	default:
		throw new Error('DOC constructor called with invalid URL');
	}
	if (! urlParams) {
		urlParams = {};
	}
	if (! (typeof(urlParams) === 'object')) {
		throw new Error('DOC constructor called with invalid URL parameters');
	}
	this.closed = false;
	this.urlParams = urlParams;
	this.user = user;
	this.password = password;
	this.token = null;
	this.timeout = undefined;
	this.refresh_in_progress = undefined;
	this.refresh();
};

require('util').inherits(DOC, require('events').EventEmitter);

DOC.prototype.refresh = function() {
	if (this.closed) {
		throw new Error('DOC client is closed');
	}
	if (this.refresh_in_progress) {
		return;
	}
	if (this.timeout) {
		clearTimeout(this.timeout);
		this.timeout = undefined;
	}
	this.refresh_in_progress =
		(Promise.resolve()
		 .then (function() {	
		 if (this.closed) {
				 throw 'closed';
			 }
			 return call(this.url, this.urlParams, this.user, this.password);
		 }.bind(this))
		 .then(function(ret) {
			 if (this.closed) {
				 throw 'closed';
			 }
			 if ((typeof(ret.expires_in) === 'string') &&
				 (ret.expires_in.match(/^[1-9]\d{1,12}$/))) {
				 ret.expires_in = Number.parseInt(body.expires_in);
			 }
			 if (! ((typeof(ret.access_token) === 'string')  &&
				   (typeof(ret.expires_in) === 'number') &&
				   (ret.expires_in > 0) &&
					(ret.expires_in <= 9999999999999))) {
				 throw new Error('Bad response from server');
			 }
			 var ttl;
			 if (ret.expires_in < 30) {
				 ttl = 10;
			 } else if (ret.expires_in < (2 * 3600)) {
				 ttl = Math.floor(ret.expires_in / 2);
			 } else {
				 ttl = 3600;
			 }
			 this.token = ret.access_token;
			 this.refresh_in_progress = undefined;
			 this.timeout = setTimeout(function() {
				 this.timeout = undefined;
				 if (! this.closed) {
					 this.refresh();
				 }
			 }.bind(this), ttl * 1000);
			 this.emit('refresh', ret.expires_in);
		 }.bind(this))
		 .catch(function(e) {
			 if (this.closed) {
				 return;
			 }
			 this.token = null;
			 this.refresh_in_progress = undefined;
			 this.timeout = setTimeout(function() {
				 this.timeout = undefined;
				 if (! this.closed) {
					 this.refresh();
				 }
			 }.bind(this), 10000);
			 this.emit('error', e);
		 }.bind(this)));
	return;
};

DOC.prototype.close = function() {
	if (this.closed) {
		throw new Error('DOC client is closed');
	}
	if (this.timeout) {
		clearTimeout(this.timeout);
		this.timeout = undefined;
	}
	this.closed = true;
	this.url = undefined;
	this.urlParams = undefined;
	this.user = undefined;
	this.password = undefined;
	this.token = undefined;
}

module.exports = DOC;
