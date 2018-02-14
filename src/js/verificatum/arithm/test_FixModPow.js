
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
// ################### Test FixModPow.js ###############################
// ######################################################################

M4_NEEDS(verificatum/arithm/FixModPow.js)dnl

var test_FixModPow = (function () {
    var prefix = "verificatum.arithm.FixModPow";

dnl Primes.
M4_INCLUDE(verificatum/arithm/test_primes.js)dnl

    var fast_equal_naive = function (testTime) {
        var e;
        var i;
        var end = test.start([prefix + " (agrees with generic)"], testTime);

        var modulus = new arithm.LargeInteger(safe_primes[0]);

        var maxWidth = 10;
        var s = 100;
        while (!test.done(end)) {

            var basis = arithm.LargeInteger.INSECURErandom(modulus.bitLength());

            for (var width = 1; width <= 8; width++) {

                var fmp = new arithm.FixModPow(basis, modulus, 20, width);

                for (var i = 1; i < modulus.bitLength() + 5; i++) {

                    var exponent = arithm.LargeInteger.INSECURErandom(i);

                    var exponents = fmp.slice(exponent);

                    var b = fmp.modPow(exponent);
                    var c = basis.modPow(exponent, modulus);

                    if (!b.equals(c)) {
                        e = "Fixed-base exponentiation is wrong!"
                            + "\nb = " + b.toHexString()
                            + "\nc = " + c.toHexString();
                        test.error(e);
                    }
                }
            }
        }
        test.end();
    };

    var run = function (testTime) {
        fast_equal_naive(testTime);
    };
    return {run: run};
})();
