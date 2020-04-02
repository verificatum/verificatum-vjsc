
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
