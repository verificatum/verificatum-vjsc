
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
