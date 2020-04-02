
// Copyright 2008-2020 Douglas Wikstrom
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

/* istanbul ignore next */
/**
 * @description Tuning functionality.
 * @namespace tune
 * @memberof verificatum.dev
 */
var tune = (function () {

    var util = verificatum.util;
    var arithm = verificatum.arithm;

    /**
     * @description
     * @param ops Operations to perform at each threshold level.
     * @return
     * @function hex28
     * @memberof verificatum.arithm.li
     */
    var square_karatsuba = function (size) {
        var x;

        for (var wordLength = 10; wordLength < 100; wordLength++) {

            var ops = size / wordLength;

            var w = arithm.li.newarray(2 * wordLength);

            var start_naive = util.time_ms();
            for (var i = 0; i < ops; i++) {
                x = arithm.li.INSECURErandom(wordLength * arithm.li.WORDSIZE);
                arithm.li.square_naive(w, x);
            }
            var time_naive = util.time_ms() - start_naive;

            var start_karatsuba = util.time_ms();
            for (var i = 0; i < ops; i++) {
                x = arithm.li.INSECURErandom(wordLength * arithm.li.WORDSIZE);
                arithm.li.square_karatsuba(w, x, 0, wordLength);
            }
            var time_karatsuba = util.time_ms() - start_karatsuba;

            console.log("" + wordLength + " " + time_naive + " "
                        + time_karatsuba + " " + (time_naive / time_karatsuba));
        }
    }

    /**
     * @description
     * @param ops Operations to perform at each threshold level.
     * @return
     * @function hex28
     * @memberof verificatum.arithm.li
     */
    var mul_karatsuba = function (size) {
        var x;
        var y;

        for (var wordLength = 10; wordLength < 100; wordLength++) {

            var ops = size / wordLength;

            var w = arithm.li.newarray(2 * wordLength);

            var start_naive = util.time_ms();
            for (var i = 0; i < ops; i++) {
                x = arithm.li.INSECURErandom(wordLength * arithm.li.WORDSIZE);
                y = arithm.li.INSECURErandom(wordLength * arithm.li.WORDSIZE);
                arithm.li.mul_naive(w, x, y);
            }
            var time_naive = util.time_ms() - start_naive;

            var start_karatsuba = util.time_ms();
            for (var i = 0; i < ops; i++) {
                x = arithm.li.INSECURErandom(wordLength * arithm.li.WORDSIZE);
                y = arithm.li.INSECURErandom(wordLength * arithm.li.WORDSIZE);
                arithm.li.mul_karatsuba(w, x, y, 0, wordLength);
            }
            var time_karatsuba = util.time_ms() - start_karatsuba;

            console.log("" + wordLength + " " + time_naive + " "
                        + time_karatsuba + " " + (time_naive / time_karatsuba));
        }
    }

    return {
        "square_karatsuba": square_karatsuba,
        "mul_karatsuba": mul_karatsuba
    };
})();
