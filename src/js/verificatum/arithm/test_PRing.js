
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
// ################### Test PRing.js ####################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PRing.js)dnl

var test_PRing = (function () {

    var identities = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (identities)"], testTime);

        for (var i = 0; i < pRings.length; i++) {
            var ONE = pRings[i].getONE();
            var ZERO = pRings[i].getZERO();

            if (!ONE.add(ZERO).equals(ONE)
                || !ZERO.add(ONE).equals(ONE)
                || !ZERO.add(ZERO).equals(ZERO)) {
                test.error("Ones and zeros don't add!");
            }

            if (!ONE.mul(ZERO).equals(ZERO)
                || !ZERO.mul(ONE).equals(ZERO)
                || !ZERO.mul(ZERO).equals(ZERO)
                || !ONE.mul(ONE).equals(ONE)) {
                test.error("Ones and zeros don't multiply!");
            }
        }

        var i = 0;
        while (!test.done(end)) {

            var ONE = pRings[i].getONE();
            var ZERO = pRings[i].getZERO();

            // Operations with zero and one.
            var x = pRings[i].randomElement(randomSource, statDist);

            var a = ZERO.add(x);
            var b = x.add(ZERO);
            if (!a.equals(x) || !b.equals(x)) {
                var e = "Addition with zero is not identity function!"
                    + "\nx = " + x.toString()
                    + "\n0 + x = " + a.toString()
                    + "\nx + 0 = " + b.toString();
                test.error(e);
            }

            a = ONE.mul(x);
            b = x.mul(ONE);
            if (!a.equals(x) || !b.equals(x)) {
                var e = "Multiplication with one is not identity!"
                    + "\nx = " + x.toString()
                    + "\n1 * x = " + a.toString()
                    + "\nx * 1 = " + b.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var addition_commutativity = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (addition commutativity)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var y = pRings[i].randomElement(randomSource, statDist);

            var a = x.add(y);
            var b = y.add(x);

            if (!a.equals(b)) {
                var e = "Addition is not commutative!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var addition_associativity = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (addition associativity)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var y = pRings[i].randomElement(randomSource, statDist);
            var z = pRings[i].randomElement(randomSource, statDist);

            var a = (x.add(y)).add(z);
            var b = x.add(y.add(z));

            if (!a.equals(b)) {
                var e = "Addition is not associative!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\nz = " + z.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var multiplication_commutativity = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (multiplication commutativity)"],
                             testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var y = pRings[i].randomElement(randomSource, statDist);

            var a = x.mul(y);
            var b = y.mul(x);

            if (!a.equals(b)) {
                var e = "Multiplication is not commutative!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var multiplication_associativity = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (multiplication associativity)"],
                             testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var y = pRings[i].randomElement(randomSource, statDist);
            var z = pRings[i].randomElement(randomSource, statDist);

            var a = (x.mul(y)).mul(z);
            var b = x.mul(y.mul(z));

            if (!a.equals(b)) {
                var e = "Multiplication is not associative!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\nz = " + z.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var distributivity = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (distributivity)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var y = pRings[i].randomElement(randomSource, statDist);
            var z = pRings[i].randomElement(randomSource, statDist);

            var a = x.mul(y.add(z));
            var b = x.mul(y).add(x.mul(z));

            if (!a.equals(b)) {
                var e = "Multiplication and addition are not transitive!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\nz = " + z.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var subtraction = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (subtraction)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var y = pRings[i].randomElement(randomSource, statDist);

            var a = x.sub(y);
            var b = a.sub(x);
            var c = b.add(y);

            if (!c.equals(pRings[i].getZERO())) {
                var e = "Subtraction is not an additive inverse!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString()
                    + "\nc = " + c.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var conversion = function (prefix, pRings, testTime) {
        var end = test.start([prefix + " (conversion)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pRings[i].randomElement(randomSource, statDist);
            var byteTree = x.toByteTree();
            var y = pRings[i].toElement(byteTree);

            if (!y.equals(x)) {
                var e = "Conversion to/from byte tree failed!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString();
                test.error(e);
            }
            i = (i + 1) % pRings.length;
        }
        test.end();
    };

    var hex = function (prefix, pGroups, testTime) {
        var e;
        var end = test.start([prefix + " (hex)"], testTime);
        for (var i = 0; i < pGroups.length; i++) {
            var x = pGroups[i].randomElement(randomSource, statDist);
            x.toString();
        }
        test.end();
    };

    return {
        identities: identities,
        addition_commutativity: addition_commutativity,
        addition_associativity: addition_associativity,
        multiplication_commutativity: multiplication_commutativity,
        multiplication_associativity: multiplication_associativity,
        distributivity: distributivity,
        subtraction: subtraction,
        conversion: conversion,
        hex: hex,
    };
})();
