
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
// ################### Test ECqPGroup.js ################################
// ######################################################################

M4_NEEDS(verificatum/arithm/ECqPGroup.js)dnl
M4_NEEDS(verificatum/arithm/test_PGroup.js)dnl

var test_ECqPGroup = (function () {
    var prefix = "verificatum.arithm.ECqPGroup";
    var arithm = verificatum.arithm;

    var pGroups = arithm.ECqPGroup.getPGroups();

    var random = function (testTime) {
        var end = test.start([prefix + " (random element)"], testTime);

        var i = 9;
        while (!test.done(end)) {

            var el = pGroups[i].randomElement(randomSource, statDist);

            // Here we change the type of the integers from sli to
            // LargeInteger.
            var x = el.value.x;
            x = new arithm.LargeInteger(x.sign, x.value);

            var y = el.value.y;
            y = new arithm.LargeInteger(y.sign, y.value);

            if (!pGroups[i].isOnCurve(x, y)) {
                var e = "Random element generation failed!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString();
                test.error(e);
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var identities = function (testTime) {
        test_PGroup.identities(prefix, pGroups, testTime);
    };
    var multiplication_commutativity = function (testTime) {
        test_PGroup.multiplication_commutativity(prefix, pGroups, testTime);
    };
    var multiplication_associativity = function (testTime) {
        test_PGroup.multiplication_associativity(prefix, pGroups, testTime);
    };
    var squaring = function (testTime) {
        var end = test.start([prefix + " (squaring)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pGroups[i].randomElement(randomSource, statDist);
            var y = pGroups[i].randomElement(randomSource, statDist);

            // We essentially add at a random translated point to
            // avoid the special formulas of squaring. We could in
            // fact implement squaring like this.
            var a = x.mul(y).mul(x).mul(y.inv());
            var b = x.square();

            if (!a.equals(b)) {
                var e = "Squaring and multiplying are not consistent!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString()
                    + "\ngroup = " + pGroups[i].toString();
                test.error(e);
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };
    var exp = function (testTime) {
        test_PGroup.exp(prefix, pGroups, testTime);
    };
    var inversion = function (testTime) {
        test_PGroup.inversion(prefix, pGroups, testTime);
    };
    var conversion = function (testTime) {
        test_PGroup.conversion(prefix, pGroups, testTime);
    };
    var encoding = function (testTime) {
        test_PGroup.encoding(prefix, pGroups, testTime);
    };
    var hex = function (testTime) {
        test_PGroup.hex(prefix, pGroups, testTime);
    };

    var run = function (testTime) {
        random(testTime);
        identities(testTime);
        multiplication_commutativity(testTime);
        multiplication_associativity(testTime);
        squaring(testTime);
        exp(testTime);
        inversion(testTime);
        conversion(testTime);
        encoding(testTime);
        hex(testTime);
    };
    return {
        pGroups: pGroups,
        run: run
    };
})();
