
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
