
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
// ################### Test PField.js ###################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PField.js)dnl
M4_NEEDS(verificatum/arithm/test_PRing.js)dnl

var test_PField = (function () {
    var prefix = "verificatum.arithm.PField";

    var getPFields = function () {
        // Set up a number of fields to be tested.
        var pFields = [];
        var i = 0;
        while (i < small_primes.length) {
            pFields[i] = new verificatum.arithm.PField(small_primes[i]);
            i++;
        }
        while (i < safe_primes.length) {
            pFields[i] = new verificatum.arithm.PField(safe_primes[i]);
        }
        return pFields;
    };
    var pFields = getPFields();

    var identities = function (testTime) {
        test_PRing.identities(prefix, pFields, testTime);
    };
    var addition_commutativity = function (testTime) {
        test_PRing.addition_commutativity(prefix, pFields, testTime);
    };
    var addition_associativity = function (testTime) {
        test_PRing.addition_associativity(prefix, pFields, testTime);
    };
    var multiplication_commutativity = function (testTime) {
        test_PRing.multiplication_commutativity(prefix, pFields, testTime);
    };
    var multiplication_associativity = function (testTime) {
        test_PRing.multiplication_associativity(prefix, pFields, testTime);
    };
    var distributivity = function (testTime) {
        test_PRing.distributivity(prefix, pFields, testTime);
    };
    var subtraction = function (testTime) {
        test_PRing.subtraction(prefix, pFields, testTime);
    };
    var conversion = function (testTime) {
        test_PRing.conversion(prefix, pFields, testTime);
    };
    var hex = function (testTime) {
        test_PRing.hex(prefix, pFields, testTime);
    };

    var inversion = function (testTime) {
        var end = test.start([prefix + " (inversion)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var ZERO = pFields[i].getZERO();
            var ONE = pFields[i].getONE();

            var x = pFields[i].randomElement(randomSource, statDist);
            while (x.equals(ZERO)) {
                x = pFields[i].randomElement(randomSource, statDist);
            }
            var y = pFields[i].randomElement(randomSource, statDist);
            while (y.equals(ZERO)) {
                y = pFields[i].randomElement(randomSource, statDist);
            }

            // We check that x * y^{-1} * x^{-1} * y.
            var a = x.mul(y.inv()).mul(x.inv()).mul(y);

            if (!a.equals(ONE)) {
                var e = "Inversion is not a multiplicative inverse!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\na = " + a.toString();
                test.error(e);
            }
            i = (i + 1) % pFields.length;
        }
        test.end();
    };

    var run = function (testTime) {
        identities(testTime);
        addition_commutativity(testTime);
        addition_associativity(testTime);
        multiplication_commutativity(testTime);
        multiplication_associativity(testTime);
        distributivity(testTime);
        subtraction(testTime);
        conversion(testTime);
        hex(testTime);
        inversion(testTime);
    };

    return {run: run};
})();
