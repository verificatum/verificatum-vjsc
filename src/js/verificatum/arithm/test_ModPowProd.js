
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
