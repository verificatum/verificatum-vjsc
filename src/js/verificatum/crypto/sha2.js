
// Copyright 2008-2018 Douglas Wikstrom
//
// This file is part of Verificatum JavaScript Cryptographic library
// (VJSC).
//
// VJSC is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// VJSC is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
// Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with VJSC. If not, see <http://www.gnu.org/licenses/>.

// ##################################################################
// ############### SHA-2 ############################################
// ##################################################################

var sha256 = (function () {

/**
 * @description Simplistic implementation of SHA-256 based on <a
 * href="http://en.wikipedia.org/wiki/SHA-2">Wikipedia SHA-2
 * pseudo-code</a>.
 * @param bytes Array of bytes.
 * @function hash
 * @memberof verificatum.crypto.sha256
 */
var hash = (function () {

    var k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
             0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
             0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
             0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
             0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
             0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
             0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
             0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
             0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
             0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

    var w = [];

    var rotr = function (w, r) {
        return w >>> r | w << 32 - r;
    };

    var H;
    var s0;
    var s1;
    var a;
    var b;
    var c;
    var d;
    var e;
    var f;
    var g;
    var h;
    
    var S0;
    var S1;
    var ch;
    var maj;
    var temp1;
    var temp2;

    var fillw = function (bytes, offset) {
        var i;
        var l;

        // Clear contents.
        for (i = 0; i < 16; i++) {
            w[i] = 0;
        }

        // Fill words until it is complete or until we run out of
        // bytes.
        l = offset;
        i = 0;
        while (i < 16 && l < bytes.length) {
            w[i] = w[i] << 8 | bytes[l];
            if (l % 4 === 3) {
                i++;
            }
            l++;
        }

        // If we ran out of bytes, then this is the last chunk of
        // bytes and there is room for a padding byte with the leading
        // bit set.
        if (i < 16) {
            w[i] = w[i] << 8 | 0x80;

            var b = 4 - l % 4 - 1;
            w[i] <<= 8 * b;
            i++;
        }
    };

    var process = function () {
        var i;

        // Expand to words from 16 to 64.
        for (i = 16; i < 64; i++) {
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // Working variables
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        for (i = 0; i < 64; i++) {

            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            ch = e & f ^ ~e & g;
            temp1 = h + S1 + ch + k[i] + w[i] | 0;
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            maj = a & b ^ a & c ^ b & c;
            temp2 = S0 + maj | 0;
 
            h = g;
            g = f;
            f = e;
            e = d + temp1 | 0;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2 | 0;
        }

        H[0] = H[0] + a | 0;
        H[1] = H[1] + b | 0;
        H[2] = H[2] + c | 0;
        H[3] = H[3] + d | 0;
        H[4] = H[4] + e | 0;
        H[5] = H[5] + f | 0;
        H[6] = H[6] + g | 0;
        H[7] = H[7] + h | 0;
    };

    /** @lends */
    return function (bytes) {

        var i;
        var j;

        // Initial hash value.
        H = [0x6a09e667,
             0xbb67ae85,
             0x3c6ef372,
             0xa54ff53a,
             0x510e527f,
             0x9b05688c,
             0x1f83d9ab,
             0x5be0cd19];

        var bs = 16 * 4;

        // Process complete blocks.
        var blocks = Math.floor(bytes.length / bs);

        var offset = 0;
        for (j = 0; j < blocks; j++) {
            fillw(bytes, offset);
            process();
            offset += bs;
        }

        var extra = bytes.length % bs;
        fillw(bytes, offset);

        if (extra + 9 > bs) {
            process();
            for (i = 0; i < 16; i++) {
                w[i] = 0;
            }
        }

        var bits = 8 * bytes.length;
        w[15] = bits & 0xFFFFFFFF;
        bits = Math.floor(bits / Math.pow(2, 32));
        w[14] = bits & 0xFFFFFFFF;

        process();

        // Convert 32-bit words to 8-bit words.
        var D = [];
        var l = 0;
        for (i = 0; i < H.length; i++) {
            for (j = 3; j >= 0; j--) {
                D[l] = H[i] >>> j * 8 & 0xFF;
                l++;
            }
        }
        return D;
    };
})();

    return {
        "hash": hash
    };

})();
