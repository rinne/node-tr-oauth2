'use strict';

const fs = require('fs');
const csv = require('csv-parser');

function csvRead(filename, spec) {
	let key;
	if (! (spec?.fields && (typeof(spec?.fields) === 'object'))) {
		throw new TypeError('Bad spec');
	}
	if ((spec.key === undefined) || (spec.key === null)) {
		key = undefined;
	} else if (spec.key && (typeof(spec.key) === 'string')) {
		if (! spec.fields[spec.key]) {
			throw new TypeError('Key missing from fields');
		}
		key = spec.key;
	} else {
		throw new TypeError('Bad key');
	}
	for (let k of Object.keys(spec.fields)) {
		if (! (spec.fields[k] && (typeof(spec.fields[k]) === 'object'))) {
			throw new TypeError('Bad field spec for ${key}');
		}
	}
	return (Promise.resolve()
			.then(function() {
				var data = key ? new Map() : [], completed = false, line = 1;
				return new Promise(function(resolve, reject) {
					(fs.createReadStream(filename)
					 .pipe(csv({ separator: ';' }))
					 .on('data', function(row) {
						 console.log(row);
						 let pr = {};
						 for (let k of Object.keys(spec.fields)) {
							 if (row[k] === undefined) {
								 if (spec.fields[k].optional) {
									 pr[k] = null;
								 } else {
									 throw new Error(`Missing field ${k}`);
								 }
							 } else {
								 pr[k] = row[k];
								 if (spec.fields[k].validator) {
									 pr[k] = spec.fields[k].validator(pr[k]);
								 }
							 }
							 if (pr[k] === undefined) {
								 throw new Error(`Invalid value ${row[k]} for ${k} on row ${line}`);
							 }
						 }
						 if (key) {
							 if (data.has(row[key])) {
								 throw new Error(`Duplicate key ${row[key]} on row ${line}`);
							 }
							 data.set(row[key], pr);
						 } else {
							 data.push(pr);
						 }
						 line++;
					 })
					 .on('end', function() {
						 if (completed) {
							 return;
						 }
						 completed = true;
						 resolve(data);
					 })
					 .on('error', function(e) {
						 if (completed) {
							 return;
						 }
						 completed = true;
						 reject(e);
					 })
					);
				});
			})
			.then(function(ret) {
				return ret;
			})
			.catch(function(e) {
				throw e;
			}));
}

module.exports = csvRead;
