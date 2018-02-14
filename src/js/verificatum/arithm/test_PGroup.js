
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
// ################### Test PGroup.js ###################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PGroup.js)dnl

var test_PGroup = (function () {

    var identities = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (identities)"], testTime);

        for (var i = 0; i < pGroups.length; i++) {
            var ONE = pGroups[i].getONE();

            if (!ONE.mul(ONE).equals(ONE)) {
                test.error("Ones don't multiply!");
            }
            if (!ONE.inv().equals(ONE)) {
                test.error("Ones don't invert!");
            }
        }

        var i = 0;
        while (!test.done(end)) {

            var ONE = pGroups[i].getONE();

            // Operations with one.
            var x = pGroups[i].randomElement(randomSource, statDist);
            var y = pGroups[i].pRing.randomElement(randomSource, statDist);

            var a = ONE.mul(x);
            var b = x.mul(ONE);
            if (!a.equals(x) || !b.equals(x)) {
                var e = "Multiplication with one is not identity function!"
                    + "\nx = " + x.toString()
                    + "\n1 * x = " + a.toString()
                    + "\nx * 1 = " + b.toString();
                test.error(e);
            }

            a = ONE.exp(y);
            if (!a.equals(ONE)) {
                var e = "Power of one is not one!"
                    + "\ny = " + y.toString()
                    + "\n1 ^ y = " + a.toString();
                test.error(e);
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var multiplication_commutativity = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (multiplication commutativity)"],
                             testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pGroups[i].randomElement(randomSource, statDist);
            var y = pGroups[i].randomElement(randomSource, statDist);

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
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var multiplication_associativity = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (multiplication associativity)"],
                             testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pGroups[i].randomElement(randomSource, statDist);
            var y = pGroups[i].randomElement(randomSource, statDist);
            var z = pGroups[i].randomElement(randomSource, statDist);

            var a = (x.mul(y)).mul(z);
            var b = x.mul(y.mul(z));

            if (!a.equals(b)) {
                var e = "Multiplication is not associative!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString()
                    + "\nz = " + z.toString()
                    + "\na = " + a.toString()
                    + "\nb = " + b.toString()
                    + "\ngroup = " + pGroups[i].toString();
                test.error(e);
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var exp = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (exponentiation linearity)"],
                             testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pGroups[i].randomElement(randomSource, statDist);

            var s = Math.max(pGroups[i].getElementOrder().bitLength() - 5, 1);
            var e = Math.max(pGroups[i].getElementOrder().bitLength() + 6, 1);

            var j = s;
            while (!test.done(end) && j < e) {

                var y = arithm.LargeInteger.INSECURErandom(j);

                var k = s;
                while (k < e) {
                    var z = arithm.LargeInteger.INSECURErandom(k);

                    var a = x.exp(y);
                    var b = x.exp(z);
                    var c = x.exp(y.add(z));

                    if (!a.mul(b).equals(c)) {
                        e = "Exponentiation is not linear in exponent!"
                            + "\nx = 0x" + x.toString()
                            + "\ny = 0x" + y.toHexString()
                            + "\nz = 0x" + z.toHexString()
                            + "\na = 0x" + a.toString()
                            + "\nb = 0x" + b.toString()
                            + "\nc = 0x" + c.toString();
                        test.error(e);
                    }
                    k++;
                }
                j++;
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var fixed = function (prefix, pGroups, testTime) {
        var e;
        var i;
        var end = test.start([prefix + " (fixed-basis exp)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pGroups[i].randomElement(randomSource, statDist);

            for (var j = 1; j < 50; j++) {

                x.fixed(j);

                var y = pGroups[i].pRing.randomElement(randomSource, statDist);

                var a = x.exp(y);
                x.fixExp = null;
                var b = x.exp(y);

                if (!a.equals(b)) {
                    e = "Fixed-base exponentiation is wrong!"
                        + "\nx = " + x.toString()
                        + "\ny = " + y.toString();
                        + "\na = " + a.toString();
                        + "\nb = " + b.toString();
                    test.error(e);
                }
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var inversion = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (inversion)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var ONE = pGroups[i].getONE();

                var x = pGroups[i].randomElement(randomSource, statDist);
            var xinv = x.inv();

            var a = x.mul(xinv);

                if (!a.equals(ONE)) {
                    var e = "Inversion is not a multiplicative inverse!"
                        + "\nx = " + x.toString()
                        + "\nxinv = " + xinv.toString()
                        + "\na = " + a.toString();
                    test.error(e);
                }
                i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var conversion = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (conversion)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            var x = pGroups[i].randomElement(randomSource, statDist);

            var byteTree = x.toByteTree();
            var y = pGroups[i].toElement(byteTree);

            if (!y.equals(x)) {
                var e = "Conversion to/from byte tree failed!"
                    + "\nx = " + x.toString()
                    + "\ny = " + y.toString();
                test.error(e);
            }
            i = (i + 1) % pGroups.length;
        }
        test.end();
    };

    var encoding = function (prefix, pGroups, testTime) {
        var end = test.start([prefix + " (encoding)"], testTime);

        var i = 0;
        while (!test.done(end)) {

            for (var j = 0; j < pGroups[i].encodeLength; j++) {

                var bytes = randomSource.getBytes(j);
                var el = pGroups[i].encode(bytes, 0, bytes.length);
                var decoded = [];
                var len = el.decode(decoded, 0);

                if (!verificatum.util.equalsArray(bytes, decoded)) {
                    var e = "Encoding/decoding failed!"
                        + "\nbytes = "
                        + verificatum.util.byteArrayToHex(bytes)
                        + "\nbytes.length = " + bytes.length
                        + "\ndecoded = "
                        + verificatum.util.byteArrayToHex(decoded)
                        + "\ndecoded.length = " + decoded.length;
                    throw Error(e);
                }
            }
            i = (i + 1) % pGroups.length;
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
        multiplication_commutativity: multiplication_commutativity,
        multiplication_associativity: multiplication_associativity,
        exp: exp,
        fixed: fixed,
        inversion: inversion,
        conversion: conversion,
        encoding: encoding,
        hex: hex,
    };
})();
