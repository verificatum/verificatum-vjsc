
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
// ################### Test ModPowProd.js ###############################
// ######################################################################

M4_NEEDS(verificatum/arithm/ModPowProd.js)dnl

var test_ModPowProd = (function () {
    var prefix = "verificatum.arithm.ModPowProd";

dnl Primes.
M4_INCLUDE(verificatum/arithm/test_primes.js)dnl

    var fast_equal_naive = function (testTime) {
        var e;
        var i;
        var end = test.start([prefix + " (agrees with naive)"], testTime);

        var modulus = new arithm.LargeInteger(safe_primes[0]);

        var maxWidth = 10;
        var s = 100;
        while (!test.done(end)) {

            for (var width = 1; width <= maxWidth; width++) {

                var bases = [];
                for (i = 0; i < width; i++) {
                    bases[i] =
                        arithm.LargeInteger.INSECURErandom(modulus.bitLength());
                    bases[i] = bases[i].mod(modulus);
                }

                var exponents = [];
                for (i = 0; i < width; i++) {
                    var len = Math.max(1, modulus.bitLength() - 5 + i);
                    exponents[i] = arithm.LargeInteger.INSECURErandom(len);
                }

                var mpp = new arithm.ModPowProd(bases, modulus);
                var a = mpp.modPowProd(exponents);
                var b = arithm.ModPowProd.naive(bases, exponents, modulus);

                if (!a.equals(b)) {
                    e = "Modular power products disagrees!"
                        + "\nwidth = " + width
                        + "\na = " + a.toHexString()
                        + "\nb = " + b.toHexString();
                    test.error(e);
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
