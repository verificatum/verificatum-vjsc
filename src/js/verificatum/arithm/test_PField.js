
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
