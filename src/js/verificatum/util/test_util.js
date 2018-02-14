
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

M4_INCLUDE(verificatum/verificatum.js)dnl
M4_INCLUDE(verificatum/dev/dev.js)dnl

// ##################################################################
// ############### Test util.js #####################################
// ##################################################################

var test_util = (function () {
    var test = verificatum.dev.test;
    var util = verificatum.util;
    var randomSource = new verificatum.crypto.RandomDevice();

    var byteArrayToFromHex = function (testTime) {
        var endEpoch =
            test.start(["verificatum.util.byteArrayToHex",
                        "verificatum.util.hexToByteArray"],
                       testTime);
        var simpleLen = 20;
        var len = 1;
        while (!test.done(endEpoch)) {

            for (var wordsize = 8; wordsize < 64; wordsize *= 2) {

                var x = util.randomArray(len, 8, randomSource);
                var hex = util.byteArrayToHex(x);
                var y = util.hexToByteArray(hex, wordsize);

                if (!util.equalsArray(x, y)) {
                    throw Error("Failed!")
                }
            }
            len = len % (simpleLen - 1) + 1;
        }
        test.end();
    };

    var byteArrayToFromAscii = function (testTime) {

        test.start(["verificatum.util.byteArrayToAscii",
                    "verificatum.util.asciiToByteArray"],
                   testTime);

        var bytes = [];
        for (var i = 0; i < 256; i++) {
            bytes[i] = i;
        }

        for (var i = 0; i < bytes.length; i++) {
            var ascii = util.byteArrayToAscii(bytes.slice(0, i));
            var bytes2 = util.asciiToByteArray(ascii);
            for (var j = 0; j < bytes2.length; j++) {
                if (bytes2[j] !== bytes[j]) {
                    throw Error("Failed!");
                }
            }
        }
        test.end();
    };

    var run = function (testTime) {
        test.startSet("verificatum/util/");
        byteArrayToFromHex(testTime);
        byteArrayToFromAscii(testTime);
    };
    return {run: run};
})();
