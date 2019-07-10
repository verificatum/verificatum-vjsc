
// Copyright 2008-2019 Douglas Wikstrom
//
// This file is part of Verificatum JavaScript Cryptographic library
// (VJSC).
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
