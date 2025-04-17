'use strict';

module.exports = (function() {
    let cr = require('node:crypto');
    let al = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let re = new RegExp('^[' + al + ']{16}$', 'i');
    let ra = {};
    al.split('').forEach((a, b) => (ra[a.toUpperCase()] = b, ra[a.toLowerCase()] = b));
    return function (k) {
        if (! re.test(k)) { throw new Error('Bad TOTP key') }
        let h = (cr
                 .createHmac('sha1', Buffer.from(k
                                                 .split('')
                                                 .map(x => (ra[x].toString(2).padStart(5, '0')))
                                                 .reduce((a, v) => (a + v), '')
                                                 .split(/(.{8})/)
                                                 .filter(x => x)
                                                 .map((x)=>(parseInt(x, 2)))))
                 .update(Math.floor(Date.now() / 30000).toString(16).padStart(16, '0'), 'hex')
                 .digest());
        let o = h[19] & 15;
        return (((((h[o] & 127) << 24) |
                  ((h[o + 1] & 255) << 16) |
                  ((h[o + 2] & 255) << 8) |
                  (h[o + 3] & 255)) % 1000000)
                .toString(10)
                .padStart(6, '0'));
    }
})();
