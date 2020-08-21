'use strict';

const fs = require('fs');
const csv = require('csv-parser');

function userFileRead(filename) {
	return (Promise.resolve()
			.then(function() {
				var users = {}, completed = false, row = 1;
				return new Promise(function(resolve, reject) {
					(fs.createReadStream(filename)
					 .pipe(csv({ separator: ';' }))
					 .on('data', function(data) {
						 if (completed) {
							 return;
						 }
						 row++;
						 Object.getOwnPropertyNames(data).forEach(function(k) {
							 data[k] = (data[k]
										.replace(/^\s*/, '')
										.replace(/\s*$/, '')
										.replace(/\s+/g, ' '));
						 });
						 if ((! data.username) && (data['0'])) {
							 console.warn('readUserFile: Malformed data on line ' +
										  filename + ':' + row +
										  ' (row ignored)');
							 return;
						 }
						 if ((! data.username) || (data.username === '')) {
							 console.warn('readUserFile: Empty or missing username on line ' +
										  filename + ':' + row +
										  ' (row ignored)');
							 return;
						 }
						 if (users[data.username]) {
							 console.warn('readUserFile: Double username on line ' +
										  filename + ':' + row +
										  ' (row ignored)');
							 return;
						 }
						 if (['password'].some(function(k) {
							 if ((! data[k]) || (data[k] === '') || (data[k] === '0')) {
								 data[k] = null;
								 return false;
							 }
							 return false;
						 })) {
							 return;
						 }
						 if (['ttl'].some(function(k) {
							 if ((! data[k]) || (data[k] === '') || (data[k] === '0')) {
								 data[k] = null;
								 return false;
							 }
							 if (data[k].match(/^[1-9][0-9]{1,8}$/)) {
								 data[k] = Number.parseInt(data[k]);
								 return false;
							 }
							 console.warn('readUserFile: Invalid valued of property ' +
										  k +
										  ' on line ' +
										  filename + ':' + row +
										  ' (row ignored)');

							 return true;
						 })) {
							 return;
						 }
						 if (['authorities', 'scope'].some(function(k) {
							 if ((! data[k]) || (data[k] === '')) {
								 data[k] = [];
								 return false;
							 }
							 data[k] = (data[k]
										.split(/\s*,\s*/)
										.map(function(s) {
											return (s.replace(/^\s*/, '')
													.replace(/\s*$/, '')
													.replace(/\s+/g, ' '));
										})
										.filter(function(s) {
											return (s !== '');
										}));
							 return false;
						 })) {
							 return;
						 }
						 users[data.username] = Object.assign({}, data);
					 })
					 .on('end', function() {
						 if (completed) {
							 return;
						 }
						 completed = true;
						 resolve(users);
					 })
					 .on('error', function(e) {
						 if (completed) {
							 return;
						 }
						 completed = true;
						 reject(e);
					 }));
				});
			})
			.then(function(ret) {
				return ret;
			})
			.catch(function(e) {
				throw e;
			}));
			
}

module.exports = userFileRead;
