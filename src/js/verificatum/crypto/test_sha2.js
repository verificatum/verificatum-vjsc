
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

// ######################################################################
// ################### Test sha2.js #####################################
// ######################################################################

var test_sha2 = (function () {
    var prefix = "verificatum.crypto.sha2";
    var crypto = verificatum.crypto;
    var util = verificatum.util;
    var test = verificatum.dev.test;

dnl This is generated, so it is not in the source tree.
dnl Inputs and outputs of sha256.
M4_INCLUDE(verificatum/crypto/test_sha256_strings.js)dnl

    var hash_strings = function (testTime) {
        test.start([prefix + " (SHA-256)"], testTime);
        for (var i = 0; i < sha256_teststrings.length; i++) {
            var pair = sha256_teststrings[i];
            var bytes = util.asciiToByteArray(pair[0]);
            var md = crypto.sha256.hash(bytes);
            var mds = util.byteArrayToHex(md);

            if (mds !== pair[1]) {
                var e = "Input: " + pair[0] +
                    "\n" + mds +
                    "\n!= " + pair[1];
                throw Error(e);
            }
        }
        test.end();
    };
dnl
dnl NIST test vectors.
dnl    var hash_singleblock = function (testTime) {
dnl        var bytes = verificatum.util.asciiToByteArray("abc");
dnl        var digest = crypto.sha256.hash(bytes);
dnl    };
dnl    var hash_doubleblock = function (testTime) {
dnl        var s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
dnl        var bytes = verificatum.util.asciiToByteArray(s);
dnl        var digest = crypto.sha256.hash(bytes);
dnl    };

    var run = function (testTime) {
dnl        hash_singleblock(testTime);
dnl        hash_doubleblock(testTime);
        hash_strings(testTime);
    };
    return {run: run};
})();
