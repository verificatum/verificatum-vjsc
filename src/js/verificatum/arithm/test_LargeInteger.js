
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
// ################### Test LargeInteger.js #############################
// ######################################################################

var test_LargeInteger = (function () {
    var prefix = "verificatum.arithm.LargeInteger";

dnl Primes.
M4_INCLUDE(verificatum/arithm/test_primes.js)dnl

    var identities = function (testTime) {
        var e;
        var end = test.start([prefix + " (identities)"], testTime);

        var ONE = arithm.LargeInteger.ONE;
        var ZERO = arithm.LargeInteger.ZERO;

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

        var i = 1;
        while (!test.done(end)) {

            // We test both positive and negative integers.
            for (var j = 0; j < 2; j++) {

                // Operations with zero and one.
                var x = verificatum.arithm.LargeInteger.INSECURErandom(i);
                if (j & 0x1) {
                    x = x.neg();
                }

                var a = ZERO.add(x);
                var b = x.add(ZERO);
                if (!a.equals(x) || !b.equals(x)) {
                    e = "Addition with zero is not identity!"
                        + "\nx = 0x" + x.toHexString()
                        + "\n0 + x = 0x" + a.toHexString()
                        + "\nx + 0 = 0x" + b.toHexString();
                    test.error(e);
                }

                a = ONE.mul(x);
                b = x.mul(ONE);
                if (!a.equals(x) || !b.equals(x)) {
                    e = "Multiplication with one is not identity!"
                        + "\nx = 0x" + x.toHexString()
                        + "\n1 * x = 0x" + a.toHexString()
                        + "\nx * 1 = 0x" + b.toHexString();
                    test.error(e);
                }
            }
            i++;
        }
        test.end();
    };

    var addition_commutativity = function (testTime) {
        var e;
        var end = test.start([prefix + " (addition commutativity)"], testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {

                    // We try all combinations of signs.
                    for (var k = 0; k < 4; k++) {
                        var x = arithm.LargeInteger.INSECURErandom(i);
                        if (k & 0x1) {
                            x = x.neg();
                        }
                        var y = arithm.LargeInteger.INSECURErandom(j);
                        if (k & 0x2) {
                            y = y.neg();
                        }

                        var a = x.add(y);
                        var b = y.add(x);

                        if (!a.equals(b)) {
                            e = "Addition is not commutative!"
                                + "\nx = 0x" + x.toHexString()
                                + "\ny = 0x" + y.toHexString()
                                + "\na = 0x" + a.toHexString()
                                + "\nb = 0x" + b.toHexString();
                            test.error(e);
                        }
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var addition_associativity = function (testTime) {
        var e;
        var end = test.start([prefix + " (addition associativity)"], testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {
                    var k = 1;
                    while (!test.done(end) && k < s) {

                        // We try all combinations of signs.
                        for (var l = 0; l < 8; l++) {
                            var x = arithm.LargeInteger.INSECURErandom(i);
                            if (l & 0x1) {
                                x = x.neg();
                            }
                            var y = arithm.LargeInteger.INSECURErandom(j);
                            if (l & 0x2) {
                                y = y.neg();
                            }
                            var z = arithm.LargeInteger.INSECURErandom(k);
                            if (l & 0x4) {
                                z = z.neg();
                            }

                            var a = (x.add(y)).add(z);
                            var b = x.add(y.add(z));

                            if (!a.equals(b)) {
                                e = "Addition is not associative!"
                                    + "\nx = 0x" + x.toHexString()
                                    + "\ny = 0x" + y.toHexString()
                                    + "\nz = 0x" + z.toHexString()
                                    + "\na = 0x" + a.toHexString()
                                    + "\nb = 0x" + b.toHexString();
                                test.error(e);
                            }
                        }
                        k++;
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var multiplication_commutativity = function (testTime) {
        var e;
        var end = test.start([prefix + " (multiplication commutativity)"],
                             testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {

                    // We try all combinations of signs.
                    for (var k = 0; k < 4; k++) {
                        var x = arithm.LargeInteger.INSECURErandom(i);
                        if (k & 0x1) {
                            x = x.neg();
                        }
                        var y = arithm.LargeInteger.INSECURErandom(j);
                        if (k & 0x2) {
                            y = y.neg();
                        }

                        var a = x.mul(y);
                        var b = y.mul(x);

                        if (!a.equals(b)) {
                            e = "Multiplication is not commutative!"
                                + "\nx = 0x" + x.toHexString()
                                + "\ny = 0x" + y.toHexString()
                                + "\na = 0x" + a.toHexString()
                                + "\nb = 0x" + b.toHexString();
                            test.error(e);
                        }
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var squaring = function (testTime) {
        var e;
        var end = test.start([prefix + " (squaring)"], testTime);

        var s = 100;
        var i = 1;
        while (!test.done(end)) {

            // We try all combinations of signs.
            for (var k = 0; k < 1; k++) {
                var x = arithm.LargeInteger.INSECURErandom(i);
                if (k & 0x1) {
                    x = x.neg();
                }

                var y = x.mul(arithm.LargeInteger.ONE);
                var a = x.square();
                var b = x.mul(y);

                if (!a.equals(b)) {
                    e = "Squaring is inconsistent with multiplication!"
                        + "\nx = 0x" + x.toHexString()
                        + "\na = 0x" + a.toHexString()
                        + "\nb = 0x" + b.toHexString();
                    test.error(e);
                }
            }
            i = ((i + 1) % s) + 1;
        }
        test.end();
    };

    var multiplication_associativity = function (testTime) {
        var e;
        var end = test.start([prefix + " (multiplication associativity)"],
                             testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {
                    var k = 1;
                    while (!test.done(end) && k < s) {

                        // We try all combinations of signs.
                        for (var l = 0; l < 8; l++) {
                            var x = arithm.LargeInteger.INSECURErandom(i);
                            if (l & 0x1) {
                                x = x.neg();
                            }
                            var y = arithm.LargeInteger.INSECURErandom(j);
                            if (l & 0x2) {
                                y = y.neg();
                            }
                            var z = arithm.LargeInteger.INSECURErandom(k);
                            if (l & 0x4) {
                                z = z.neg();
                            }

                            var a = (x.mul(y)).mul(z);
                            var b = x.mul(y.mul(z));

                            if (!a.equals(b)) {
                                e = "Multiplication is not associative!"
                                    + "\nx = 0x" + x.toHexString()
                                    + "\ny = 0x" + y.toHexString()
                                    + "\nz = 0x" + z.toHexString()
                                    + "\na = 0x" + a.toHexString()
                                    + "\nb = 0x" + b.toHexString();
                                test.error(e);
                            }
                        }
                        k++;
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var distributivity = function (testTime) {
        var e;
        var end = test.start([prefix + " (distributivity)"], testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {
                    var k = 1;
                    while (!test.done(end) && k < s) {

                        // We try all combinations of signs.
                        for (var l = 0; l < 8; l++) {
                            var x = arithm.LargeInteger.INSECURErandom(i);
                            if (l & 0x1) {
                                x = x.neg();
                            }
                            var y = arithm.LargeInteger.INSECURErandom(j);
                            if (l & 0x2) {
                                y = y.neg();
                            }
                            var z = arithm.LargeInteger.INSECURErandom(k);
                            if (l & 0x4) {
                                z = z.neg();
                            }

                            var a = x.mul(y.add(z));
                            var b = x.mul(y).add(x.mul(z));

                            if (!a.equals(b)) {
                                e = "Multiplication and addition are not "
                                    + "transitive!"
                                    + "\nx = 0x" + x.toHexString()
                                    + "\ny = 0x" + y.toHexString()
                                    + "\nz = 0x" + z.toHexString()
                                    + "\na = 0x" + a.toHexString()
                                    + "\nb = 0x" + b.toHexString();
                                test.error(e);
                            }
                        }
                        k++;
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var division_with_zero_remainder = function (testTime) {
        var e;
        var end = test.start([prefix + " (division without remainder)"],
                             testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {

                    var x = arithm.LargeInteger.INSECURErandom(i);
                    var y = arithm.LargeInteger.INSECURErandom(j);
                    while (y.iszero()) {
                        y = arithm.LargeInteger.INSECURErandom(j);
                    }

                    var p = x.mul(y);
                    var q = p.div(y);

                    if (!q.equals(x)) {
                        e = "Division with zero remainder failed!"
                            + "\nx = 0x" + x.toHexString()
                            + "\ny = 0x" + y.toHexString()
                            + "\np = 0x" + p.toHexString()
                            + "\nq = 0x" + q.toHexString();
                        test.error(e);
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var division_with_remainder = function (testTime) {
        var e;
        var end = test.start([prefix + " (division with remainder)"], testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {

                    var x = arithm.LargeInteger.INSECURErandom(i);
                    var y = arithm.LargeInteger.INSECURErandom(j);
                    while (y.iszero()) {
                        y = arithm.LargeInteger.INSECURErandom(j);
                    }

                    var q = x.div(y);
                    var r = x.mod(y);
                    var xx = q.mul(y).add(r);

                    if (!xx.equals(x)) {
                        e = "Division with remainder failed!"
                            + "\nx = 0x" + x.toHexString()
                            + "\ny = 0x" + y.toHexString()
                            + "\nq = 0x" + q.toHexString()
                            + "\nr = 0x" + r.toHexString()
                            + "\nxx = 0x" + xx.toHexString();
                        test.error(e);
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var modpow = function (testTime) {
        var e;
        var end = test.start([prefix + " (modpow)"], testTime);

        var one = arithm.LargeInteger.ONE.modPow(arithm.LargeInteger.ZERO,
                                                 arithm.LargeInteger.TWO);
        if (!one.equals(arithm.LargeInteger.ONE)) {
            throw Error("Failed to exponentiate with zero!");
        }


        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {
                    var k = 1;
                    while (!test.done(end) && k < s) {

                        var x = arithm.LargeInteger.INSECURErandom(i);
                        var y1 = arithm.LargeInteger.INSECURErandom(j);
                        var y2 = arithm.LargeInteger.INSECURErandom(j);

                        var ysum = y1.add(y2);

                        var z = arithm.LargeInteger.INSECURErandom(k);
                        while (z.iszero()) {
                            z = arithm.LargeInteger.INSECURErandom(k);
                        }

                        // Check that 1^y1 = 0 mod 1, and
                        // 1^y1 = 1 mod z for z > 1.
                        var c = arithm.LargeInteger.ONE.modPow(y1, z);
                        if (z.equals(arithm.LargeInteger.ONE)) {
                            if (!c.equals(arithm.LargeInteger.ZERO)) {
                                e = "Power of one modulo one is not zero!"
                                    + "\ny1 = 0x" + y1.toHexString()
                                    + "\nz = 0x" + z.toHexString()
                                    + "\nc = 0x" + c.toHexString();
                                test.error(e);
                            }
                        } else if (!c.equals(arithm.LargeInteger.ONE)) {
                            e = "Power of one modulo modulus > 1 is not one!"
                                + "\ny1 = 0x" + y1.toHexString()
                                + "\nz = 0x" + z.toHexString()
                                + "\nc = 0x" + c.toHexString();
                            test.error(e);
                        }

                        var a = x.modPow(y1, z);

                        // Consistency with naive modpow
                        var b = x.modPow(y1, z, true);

                        if (!a.equals(b)) {
                            e = "Modpow and naive modpow are inconsistent!"
                                + "\nx = 0x" + x.toHexString()
                                + "\ny1 = 0x" + y1.toHexString()
                                + "\ny2 = 0x" + y2.toHexString()
                                + "\nz = 0x" + z.toHexString()
                                + "\na = 0x" + a.toHexString()
                                + "\nb = 0x" + b.toHexString();
                            test.error(e);
                        }

                        // Linearity.
                        b = x.modPow(y2, z);
                        var ab = a.mul(b);
                        var c = ab.mod(z);
                        var cc = x.modPow(ysum, z);

                        if (!cc.equals(c)) {
                            e = "Modpow is not linear in exponent!"
                                + "\nx = 0x" + x.toHexString()
                                + "\ny1 = 0x" + y1.toHexString()
                                + "\ny2 = 0x" + y2.toHexString()
                                + "\nysum = 0x" + ysum.toHexString()
                                + "\nz = 0x" + z.toHexString()
                                + "\na = 0x" + a.toHexString()
                                + "\nb = 0x" + b.toHexString()
                                + "\nab = 0x" + ab.toHexString()
                                + "\nc = 0x" + c.toHexString()
                                + "\ncc = 0x" + cc.toHexString();
                            test.error(e);
                        }
                        k++;
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var egcd = function (testTime) {
        var e;
        var end = test.start([prefix + " (egcd)"], testTime);

        var s = 100;
        while (!test.done(end)) {
            var i = 1;
            while (!test.done(end) && i < s) {
                var j = 1;
                while (!test.done(end) && j < s) {

                    var x = arithm.LargeInteger.INSECURErandom(i);
                    var y = arithm.LargeInteger.INSECURErandom(j);

                    var res = x.egcd(y);

                    var a = res[0];
                    var b = res[1];
                    var v = res[2];

                    var c = a.mul(x).add(b.mul(y));

                    if (!c.equals(v)) {
                        e = "Linear function does not give GCD!"
                            + "\nx = 0x" + x.toHexString()
                            + "\ny = 0x" + y.toHexString()
                            + "\na = 0x" + a.toHexString()
                            + "\nb = 0x" + b.toHexString()
                            + "\nv = 0x" + v.toHexString()
                            + "\nc = 0x" + c.toHexString();
                        test.error(e);
                    }
                    j++;
                }
                i++;
            }
        }
        test.end();
    };

    var legendre = function (testTime) {
        var e;
        var end = test.start([prefix + " (legendre)"], testTime);

        var primes = [];
        for (var i = 0; i < safe_primes.length; i++) {
            primes.push(new arithm.LargeInteger(safe_primes[i]))
        }

        var s = 100;
        var i = 1;
        while (!test.done(end)) {

            for (var j = 0; j < primes.length; j++) {

                var x = arithm.LargeInteger.INSECURErandom(i);
                var y = x.neg();

                // Here we use the fact that -1 is a non-residue.
                var ly = y.legendre(primes[j]);
                var lx = x.legendre(primes[j]);

                if ((x.iszero() && (lx !== 0 || ly !== 0)) ||
                    (!x.iszero() &&
                     (Math.abs(lx) !== 1 || Math.abs(ly) !== 1 || lx === ly))) {
                    e = "Computation of Legendre symbol failed!"
                        + "\nx = 0x" + x.toHexString()
                        + "\ny = 0x" + y.toHexString()
                        + "\nlx = 0x" + lx
                        + "\nly = 0x" + ly;
                    test.error(e);
                }
            }
            if (i === s) {
                i = 1;
            } else {
                i++;
            }
        }
        test.end();
    };

    var sqrt = function (testTime) {
        var e;
        var end = test.start([prefix + " (sqrt)"], testTime);

        var primes = [];
        for (var i = 0; i < safe_primes.length; i++) {
            primes.push(new arithm.LargeInteger(safe_primes[i]))
        }

        var s = 100;
        var i = 1;
        while (!test.done(end)) {

            for (var j = 0; j < primes.length; j++) {

                var x = arithm.LargeInteger.INSECURErandom(i);
                var y = x.mul(x).mod(primes[j]);
                var z = y.modSqrt(primes[j]);

                // We don't care which of the roots we get.
                var w = z.mul(z).mod(primes[j]);

                if (!w.equals(y)) {
                    e = "Computation of square root failed!"
                        + "\np = 0x" + primes[j].toHexString()
                        + "\nx = 0x" + x.toHexString()
                        + "\ny = 0x" + y.toHexString()
                        + "\nz = 0x" + z.toHexString()
                        + "\nw = 0x" + w.toHexString();
                    test.error(e);
                }
            }
            if (i === s) {
                i = 1;
            } else {
                i++;
            }
        }
        test.end();
    };

    var conversion = function (testTime) {
        var e;
        var end = test.start([prefix + " (conversion)"], testTime);

        var s = 100;
        var i = 1;
        while (!test.done(end)) {

            var x = arithm.LargeInteger.INSECURErandom(i);
            var byteArray = x.toByteArray();
            var y = new verificatum.arithm.LargeInteger(byteArray);

            if (!x.equals(y)) {
                e = "Conversion failed!"
                    + "\nx = 0x" + x.toHexString()
                    + "\ny = 0x" + y.toHexString();
                test.error(e);
            }

            var byteTree = x.toByteArray();
            var z = new verificatum.arithm.LargeInteger(byteTree);

            if (!x.equals(z)) {
                e = "Conversion failed!"
                    + "\nx = 0x" + x.toHexString()
                    + "\nz = 0x" + z.toHexString();
                test.error(e);
            }

            if (i === s) {
                i = 1;
            } else {
                i++;
            }
        }
        test.end();
    };

    var shifting = function (testTime) {
        var e;
        var end = test.start([prefix + " (shift)"], testTime);

        var s = 100;
        var i = 1;
        while (!test.done(end)) {

            var x = arithm.LargeInteger.INSECURErandom(i);

            for (var j = 0; j <= 64; j++) {
                var lx = x.shiftLeft(j);
                var y = lx.shiftRight(j);

                if (!x.equals(y)) {
                    e = "Shift failed!"
                        + "\nx = 0x" + x.toHexString()
                        + "\ny = 0x" + y.toHexString();
                    test.error(e);
                }
            }

            var rx = x.shiftRight(i + 1);
            if (!rx.equals(arithm.LargeInteger.ZERO)) {
                e = "Right shift failed!"
                    + "\nx = 0x" + x.toHexString()
                    + "\ny = 0x" + y.toHexString();
                test.error(e);
            }


            if (i === s) {
                i = 1;
            } else {
                i++;
            }
        }
        test.end();
    };

    var hex = function (testTime) {
        var e;
        var end = test.start([prefix + " (hex)"], testTime);

        var x = arithm.LargeInteger.INSECURErandom(100);
        var xhex = x.toHexString();
        var x2 = new arithm.LargeInteger(xhex);
        if (!x.equals(x2)) {
            throw Error("Failed to convert positive integer to hex! ("
                        + xhex + ")");
        }

        var y = arithm.LargeInteger.INSECURErandom(100);
        var yhey = y.toHexString();
        var y2 = new arithm.LargeInteger(yhey);
        if (!y.equals(y2)) {
            throw Error("Failed to convert negative integer to hex! ("
                        + yhey + ")");
        }

        test.end();
    };

    var run = function (testTime) {
        identities(testTime);
        addition_commutativity(testTime);
        addition_associativity(testTime);
        squaring(testTime);
        multiplication_commutativity(testTime);
        multiplication_associativity(testTime);
        distributivity(testTime);
        division_with_zero_remainder(testTime);
        division_with_remainder(testTime);
        modpow(testTime);
        egcd(testTime);
        legendre(testTime);
        sqrt(testTime);
        conversion(testTime);
        shifting(testTime);
        hex(testTime);
    };
    return {run: run};
})();
