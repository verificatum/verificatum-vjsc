
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
// ################### sli ##############################################
// ######################################################################


/**
 * Thin layer on top of the li module that provides mutable signed
 * integers with basic modular arithmetic along with a few low level
 * routines that requires signed integers to implement.
 *
 * <p>
 *
 * It also provides a minimal container class SLI that represents a
 * signed integer. All operations on are executed on pre-existing SLI
 * instances, so it is the responsibility of the programmer to ensure
 * that data fits inside the allocated space.
 *
 * <p>
 *
 * This approach is motivated by the need to preserve efficiency and
 * still encapsulate as much implementation details as possible.
 *
 * @namespace sli
 * @memberof verificatum.arithm
 */
var sli = (function () {

    /**
     * @description Container class for signed mutable integers with space
     * handled by the programmer. Instantiated with sign and value, with a
     * length of the underlying array for an uninitialized instance, or
     * with no parameters.
     * @param first Empty, sign, or number of words in empty instance.
     * @param second Empty or array containing value.
     * @return Instance of a container for signed integers.
     * @class SLI
     * @memberof verificatum.arithm.sli
     */
    function SLI(first, second) {
        if (typeof first === "undefined") {
            this.sign = 1;
            this.value = [];
        } else if (typeof second === "undefined") {
            this.sign = 1;
            this.value = li.newarray(first);
        } else {
            this.sign = first;
            this.value = second;
        }
        this.length = this.value.length;
    }
    SLI.prototype = Object.create(ArithmObject.prototype);
    SLI.prototype.constructor = SLI;

    /**
     * @description Truncates the input to the shortest possible array
     * that represents the same absolute value in two's complement, i.e.,
     * there is always a leading zero bit.
     * @param x Array to be truncated.
     * @param mask_top Word used to normalize.
     * @function normalize
     * @memberof verificatum.arithm.sli
     */
    var normalize = function (x, mask_top) {
        li.normalize(x.value, mask_top);
        this.length = x.value.length;
    };

    /**
     * @description Resizes the underlying array to the given length.
     * @param a SLI to be resized.
     * @param len New length of SLI.
     * @function resize
     * @memberof verificatum.arithm.sli
     */
    var resize = function (a, len) {
        li.resize(a.value, len);
        a.length = a.value.length;
    };

    /**
     * @description Returns the sign of a number.
     * @param n A Javascript "number".
     * @return Sign of number as -1, 0, or 1.
     * @function sign
     * @memberof verificatum.arithm.sli
     */
    var sign = function (n) {
        if (n > 0) {
            return 1;
        } else if (n === 0) {
            return 0;
        } else {
            return -1;
        }
    };

    /**
     * @description Sets a = b, where b may be an SLI instance or a
     * "number"
     *
     * <p>
     *
     * ASSUMES: b has L words and a has at least L limbs. If b is a
     * "number", then it is assumed that 0 <= |b| < 2^M4_WORDSIZE.
     *
     * @param a SLI holding the result.
     * @param b Integer value represented as a SLI or Javascript "number".
     * @function set
     * @memberof verificatum.arithm.sli
     */
    var set = function (a, b) {
        if (typeof b === "number") {
            a.sign = sign(b);
            li.setzero(a.value);
            a.value[0] = a.sign * b;
        } else {
            a.sign = b.sign;
            li.set(a.value, b.value);
        }
    };

    /**
     * @description Returns a copy of a, where the length of the
     * underlying array is len if this increases it.
     * @param a Original array.
     * @param len Length of resulting SLI if it is larger than the
     * length of the original SLI.
     * @return Copy of original SLI.
     * @function copy
     * @memberof verificatum.arithm.sli
     */
    var copy = function (a, len) {
        if (typeof len === "undefined") {
            len = a.length;
        }
        return new SLI(a.sign, li.copyarray(a.value, len));
    };

    /**
     * @description Returns -1, 0, or 1 depending on if a < b, a == b, or
     * a > b.
     * @param a Left SLI.
     * @param b Right SLI.
     * @return Value of comparison predicate on a and b.
     * @function cmp
     * @memberof verificatum.arithm.sli
     */
    var cmp = function (a, b) {
        if (a.sign < b.sign) {
            return -1;
        } else if (a.sign > b.sign) {
            return 1;
        } else if (a.sign === 0) {
            return 0;
        }
        return li.cmp(a.value, b.value) * a.sign;
    };

    /**
     * @description Returns true or false depending on if a = b or not.
     * @param a Left SLI.
     * @param b Right SLI.
     * @return True or false depending on if the SLIs represent the same
     * integer or not.
     * @function equals
     * @memberof verificatum.arithm.sli
     */
    var equals = function (a, b) {
        return a.sign === b.sign && li.cmp(a.value, b.value) === 0;
    };

    /**
     * @description Returns true or false depending on a = 0 or not.
     * @param a Integer represented as a SLI.
     * @return True or false depending on if a is zero or not.
     * @function iszero
     * @memberof verificatum.arithm.sli
     */
    var iszero = function (a) {
        return a.sign === 0;
    };

    /**
     * @description Returns true or false depending on a = 1 or not.
     * @param a Integer represented as a SLI.
     * @return True or false depending on if a is zero or not.
     * @function iszero
     * @memberof verificatum.arithm.sli
     */
    var isone = function (a) {
        return a.sign === 1 && a.value[0] === 1 && li.msword(a.value) === 0;
    };

    /**
     * @description Shifts the given number of bits within the SLI,
     * i.e., the allocated space is not expanded.
     *
     * <p>
     *
     * ASSUMES: offset >= 0.
     *
     * @param x SLI to be shifted.
     * @param offset Number of bit positions to shift.
     * @function shiftleft
     * @memberof verificatum.arithm.sli
     */
    var shiftleft = function (a, offset) {
        li.shiftleft(a.value, offset);
    };

    /**
     * @description Shifts the given number of bits to the right within
     * the allocated space, i.e., the space is not reduced.
     *
     * <p>
     *
     * ASSUMES: offset >= 0.
     *
     * @param x SLI to be shifted.
     * @param offset Number of bit positions to shift.
     * @function shiftright
     * @memberof verificatum.arithm.sli
     */
    var shiftright = function (a, offset) {
        li.shiftright(a.value, offset);
        if (li.iszero(a.value)) {
            a.sign = 0;
        }
    };

    /**
     * @description Sets a = b + c.
     *
     * <p>
     *
     * ASSUMES: b and c have B and B' bits and a can store B + B' + 1
     * bits, or B + B' bits depending on if the signs of b and c are equal
     * or not.
     *
     * @param a SLI holding the result.
     * @param b Left term.
     * @param c Right term.
     * @function add
     * @memberof verificatum.arithm.sli
     */
    var add = function (a, b, c) {
        var w = a.value;
        var x = b.value;
        var y = c.value;

        // x + y  or  -x + -y.
        if (b.sign === c.sign) {

            li.add(w, x, y);
            if (b.sign === 0) {
                a.sign = -c.sign;
            } else {
                a.sign = b.sign;
            }

            // -x + y  or  x + -y.
        } else {

            // x >= y.
            if (li.cmp(x, y) >= 0) {
                li.sub(w, x, y);
                a.sign = b.sign;

                // x < y.
            } else {
                li.sub(w, y, x);
                a.sign = c.sign;
            }
        }

        if (li.iszero(w)) {
            a.sign = 0;
        }
    };

    /**
     * @description Sets a = b - c.
     *
     * <p>
     *
     * ASSUMES: b and c have B and B' bits and a can store B + B' + 1
     * bits, or B + B' bits depending on if the signs of b and c are
     * distinct or not.
     *
     * @param a SLI holding the result.
     * @param b Left term.
     * @param c Right term.
     * @function sub
     * @memberof verificatum.arithm.sli
     */
    var sub = function (a, b, c) {
        var w = a.value;
        var x = b.value;
        var y = c.value;

        // x - y  or  -x - -y.
        if (b.sign === c.sign) {

            // x >= y.
            if (li.cmp(x, y) >= 0) {
                li.sub(w, x, y);
                a.sign = b.sign;
                // x < y.
            } else {
                li.sub(w, y, x);
                a.sign = -b.sign;
            }

            // -x - y  or  x - -y.
        } else {

            li.add(w, x, y);
            if (b.sign === 0) {
                a.sign = -c.sign;
            } else {
                a.sign = b.sign;
            }
        }

        if (li.iszero(w)) {
            a.sign = 0;
        }
    };

    /**
     * @description Sets a = b * c.
     *
     * <p>
     *
     * ASSUMES: b and c have L and L' limbs and a has at least L + L' limbs.
     *
     * @param a SLI holding the result.
     * @param b Left factor.
     * @param c Right factor.
     * @function mul
     * @memberof verificatum.arithm.sli
     */
    var mul = (function () {

        var t = [];

        return function (a, b, c) {
            if (a === b || a === c) {
                if (t.length !== a.length) {
                    li.resize(t, a.length);
                }
                li.mul(t, b.value, c.value);
                li.set(a.value, t);
            } else {
                li.mul(a.value, b.value, c.value);
            }
            a.sign = b.sign * c.sign;
        };
    })();

    /**
     * @description Sets a = b * c, where c is a Javascript "number".
     *
     * <p>
     *
     * ASSUMES: b has L limbs, c is a Javascript "number" such that 0 <=
     * |c| < 2^M4_WORDSIZE, and a has at least L + 1 limbs.
     *
     * @param a SLI holding the result.
     * @param b Left factor.
     * @param c Right factor.
     * @function mul_number
     * @memberof verificatum.arithm.sli
     */
    var mul_number = (function () {
        var C = new SLI(1);

        /** @lends */
        return function (a, b, c) {
            set(C, c);
            mul(a, b, C);
        };
    })();

    /**
     * @description Sets a = b^2.
     *
     * <p>
     *
     * ASSUMES: b has L words and a has at least 2 * L limbs.
     *
     * @param a SLI holding the result.
     * @param b Factor.
     * @function square
     * @memberof verificatum.arithm.sli
     */
    var square = function (a, b) {
        li.square(a.value, b.value);
        a.sign = b.sign * b.sign;
    };

    /**
     * @description Computes q, r such that q = a / b + r with a / b and r
     * rounded with sign, in particular, if b is positive, then 0 <= r <
     * b. Then it sets a = r. We are faithful to the mathematical
     * definition for signs.
     *
     * <p>
     *
     * ASSUMES: a and b are positive, a has L words and at least L + 2
     * limbs (i.e., two leading unused zero words), b has L' limbs, and q
     * has at least L'' = max{L - L', L', 0} + 1 limbs and will finally
     * hold a result with at most L'' words and a leading zero limb.
     *
     * @param q SLI holding the quotient.
     * @param a Dividend.
     * @param b Divisor.
     * @function div_qr
     * @memberof verificatum.arithm.sli
     */
    var div_qr = function (q, a, b) {

        var qsign;
        var asign;

        li.div_qr(q.value, a.value, b.value);

        // Division without remainder.
        if (li.iszero(a.value)) {

            qsign = a.sign * b.sign;
            asign = 0;

            // Division with remainder, so we need to round.
        } else {

            if (a.sign * b.sign === 1) {
                asign = a.sign;
                qsign = a.sign;
            } else {

                // This is safe since a.value < b.value and a.value has at
                // least one more limb than b.value.
                li.sub(a.value, b.value, a.value);

                // This is safe, since q has an additional limb.
                li.add(q, q, [1]);
                asign = b.sign;
                qsign = a.sign;
            }
        }
        q.sign = qsign;
        a.sign = asign;
    };

    /**
     * @description Sets a = b mod c (this is merely syntactic sugar for
     * div_qr).
     * @param a SLI holding the result.
     * @param b Dividend.
     * @param c Modulus.
     * @function mod
     * @memberof verificatum.arithm.sli
     */
    var mod = (function () {

        // Temporary space for quotient and remainder.
        var q = new SLI();
        var r = new SLI();

        /** @lends */
        return function (a, b, c) {

            // Resize temporary space if needed. This is conservative.
            var qlen = b.length + 1;
            if (q.length < qlen) {
                resize(q, qlen);
            }
            var rlen = b.length + 2;
            if (r.length < rlen) {
                resize(r, rlen);
            }

            // Copy b to temporary remainder, reduce and set result.
            set(r, b);
            div_qr(q, r, c);
            set(a, r);
        };
    })();

    // Help function for egcd. Not exposed in interface. Consult HAC 14.61
    // (5th printing + errata) for information.
    var egcd_binary_reduce = function (u, A, B, x, y) {

        while ((u.value[0] & 0x1) === 0) {

            // u = u / 2.
            shiftright(u, 1);

            // A = 0 mod 2 and B = 0 mod 2.
            if ((A.value[0] & 0x1) === 0 && (B.value[0] & 0x1) === 0) {

                // A = A / 2 and B = B / 2.
                shiftright(A, 1);
                shiftright(B, 1);

            } else {

                // A = (A + y) / 2.
                add(A, A, y);
                shiftright(A, 1);

                // B = (B - x) / 2.
                sub(B, B, x);
                shiftright(B, 1);
            }
        }
    };

    /**
     * @description Sets a, b, and v such that a * x + b * y = v and v is
     * the greatest common divisor of x and y.
     *
     * <p>
     *
     * References: HAC 14.61 (5th printing + errata)
     *
     * @param a Linear coefficient of Bezout expression.
     * @param b Linear coefficient of Bezout expression.
     * @param v Greatest common divisor of x and y.
     * @param x Left integer.
     * @param y Right integer.
     * @function egcd
     * @memberof verificatum.arithm.sli
     */
    var egcd = (function () {

        // Temporary space.
        var xs = new SLI();
        var ys = new SLI();

        var A = new SLI();
        var B = new SLI();
        var C = new SLI();
        var D = new SLI();

        var u = new SLI();

        /** @lends */
        return function (a, b, v, x, y) {

            if (iszero(x) || iszero(y)) {
                set(a, 0);
                set(b, 0);
                set(v, 0);
                return;
            }

            var len = Math.max(x.length, y.length) + 1;
            if (A.length !== len) {
                resize(xs, len);
                resize(ys, len);

                resize(A, len);
                resize(B, len);
                resize(C, len);
                resize(D, len);
                resize(u, len);
            }

            set(xs, x);
            set(ys, y);

            set(A, 1);
            set(B, 0);
            set(C, 0);
            set(D, 1);

            // Extract all common factors of two.
            var common_twos = Math.min(li.lsbit(xs.value), li.lsbit(ys.value));
            shiftright(xs, common_twos);
            shiftright(ys, common_twos);

            set(u, xs);
            set(v, ys);

            // Use binary laws for greatest common divisors.
            while (!iszero(u)) {

                egcd_binary_reduce(u, A, B, xs, ys);
                egcd_binary_reduce(v, C, D, xs, ys);

                if (cmp(u, v) >= 0) {

                    sub(u, u, v);
                    sub(A, A, C);
                    sub(B, B, D);

                } else {

                    sub(v, v, u);
                    sub(C, C, A);
                    sub(D, D, B);
                }
            }

            set(a, C);
            set(b, D);

            shiftleft(v, common_twos);
        };
    })();

    /**
     * @description Sets a such that w * x = 1 mod p.
     *
     * <p>
     *
     * ASSUMES: p > 0 is on odd prime.
     *
     * <p>
     *
     * References: HAC 14.61
     *
     * @param w SLI holding the result.
     * @param x Integer to invert.
     * @param p Positive odd prime modulus.
     * @function egcd
     * @memberof verificatum.arithm.sli
     */
    var modinv = (function () {

        // Temporary space.
        var a = new SLI();
        var b = new SLI();
        var v = new SLI();

        /** @lends */
        return function (w, x, p) {

            var len = Math.max(p.length, x.length);
            if (a.length !== len) {
                resize(a, len);
                resize(b, len);
                resize(v, len);
            }

            egcd(a, b, v, x, p);

            if (a.sign < 0) {
                add(w, p, a);
            } else {
                set(w, a);
            }
        };
    })();

    /**
     * @description Sets w = b^e mod m.
     *
     * <p>
     *
     * ASSUMES: b >= 0, e >= 0, and m >= 1, and w, b and m have L limbs.
     *
     * @param w SLI holding the result.
     * @param b Basis integer.
     * @param e Exponent.
     * @param m Modulus.
     * @function modpow
     * @memberof verificatum.arithm.sli
     */
    var modpow = function (w, b, e, m) {
        li.modpow(w.value, b.value, e.value, m.value);
        w.sign = 1;
    };

    /**
     * @description Returns (a | b), i.e., the Legendre symbol of a modulo
     * b for an odd prime b. (This is essentially a GCD algorithm that
     * keeps track of the symbol.)
     *
     * <p>
     *
     * References: HAC 2.149.
     *
     * @param a Integer modulo b.
     * @param b An odd prime modulus.
     * @return Legendre symbol of this instance modulo the input.
     * @function legendre
     * @memberof verificatum.arithm.sli
     */
    var legendre = function (a, b) {

        a = copy(a);
        b = copy(b);

        var s = 1;
        for (;;) {

            if (iszero(a)) {

                return 0;

            } else if (isone(a)) {

                return s;

            } else {

                // a = 2^e * a'
                var e = li.lsbit(a.value);

                // a = a'.
                shiftright(a, e);

                // Least significant words of a and b.
                var aw = a.value[0];
                var bw = b.value[0];

                // e = 1 mod 2 and b = 3,5 mod 8.
                if (e % 2 === 1 && (bw % 8 === 3 || bw % 8 === 5)) {
                    s = -s;
                }
                // b = a = 3 mod 4.
                if (bw % 4 === 3 && aw % 4 === 3) {
                    s = -s;
                }

                // Corresponds to finding the GCD.
                if (isone(a)) {
                    return s;
                }

                // Replacement for recursive call.
                mod(b, b, a);

                var t = a;
                a = b;
                b = t;
            }
        }
    };

    /**
     * @description Sets w to an integer such that w^2 = x mod p, i.e., it
     * computes the square root of an integer modulo a positive odd prime
     * employing the Shanks-Tonelli algorithm.
     * @param w Holding the result.
     * @param x Integer of which the square root is computed.
     * @param p Positive odd prime modulus.
     * @function legendre
     * @memberof verificatum.arithm.sli
     */
    var modsqrt = (function () {

        var ONE = new SLI(1);
        set(ONE, 1);

        var TWO = new SLI(1);
        set(TWO, 2);

        var a = new SLI();
        var n = new SLI();
        var v = new SLI();
        var k = new SLI();
        var r = new SLI();
        var z = new SLI();
        var c = new SLI();
        var tmp = new SLI();

        /** @lends */
        return function (w, x, p) {

            var len = 2 * (li.msword(p.value) + 1);
            if (a.length !== len) {
                resize(a, len);
                resize(n, len);
                resize(v, len);
                resize(k, len);
                resize(r, len);
                resize(z, len);
                resize(c, len);
                resize(tmp, len);
            }
            mod(a, x, p);

            if (iszero(a)) {
                set(w, 0);
                return;
            }

            if (equals(p, TWO)) {
                set(w, a);
                return;
            }

            // p = 3 mod 4
            if ((p.value[0] & 0x3) === 0x3) {

                // v = p + 1
                add(v, p, ONE);

                // v = v / 4
                shiftright(v, 2);

                // return a^v mod p
                // return --> a^((p + 1) / 4) mod p
                modpow(w, a, v, p);
                return;
            }

            // Compute k and s, where p = 2^s * (2 * k + 1) + 1

            // k = p - 1
            sub(k, p, ONE);

            // (p - 1) = 2^s * k
            var s = li.lsbit(k.value);
            shiftright(k, s);

            // k = k - 1
            sub(k, k, ONE);

            // k = k / 2
            shiftright(k, 1);

            // r = a^k mod p
            modpow(r, a, k, p);

            // n = r^2 mod p
            mul(tmp, r, r);
            mod(n, tmp, p);

            // n = n * a mod p
            mul(tmp, n, a);
            mod(n, tmp, p);

            // r = r * a mod p
            mul(tmp, r, a);
            mod(r, tmp, p);

            if (isone(n)) {
                set(w, r);
                return;
            }

            // Generate a quadratic non-residue
            set(z, 2);

            // while z quadratic residue
            while (legendre(z, p) === 1) {

                // z = z + 1
                add(z, z, ONE);
            }

            set(v, k);

            // v = 2k
            shiftleft(v, 1);

            // v = 2k + 1
            add(v, v, ONE);

            // c = z^v mod p
            modpow(c, z, v, p);

            var t = 0;
            while (cmp(n, ONE) > 0) {

                // k = n
                set(k, n);

                // t = s
                t = s;
                s = 0;

                // k != 1
                while (!isone(k)) {

                    // k = k^2 mod p
                    mul(tmp, k, k);
                    mod(k, tmp, p);

                    // s = s + 1
                    s++;
                }

                // t = t - s
                t -= s;

                // v = 2^(t-1)
                set(v, ONE);
                shiftleft(v, t - 1);

                // c = c^v mod p
                modpow(tmp, c, v, p);
                set(c, tmp);

                // r = r * c mod p
                mul(tmp, r, c);
                mod(r, tmp, p);

                // c = c^2 mod p
                mul(tmp, c, c);
                mod(c, tmp, p);

                // n = n * c mod p
                mul(tmp, n, c);
                mod(n, tmp, p);
            }
            set(w, r);
        };
    })();



    /**
     * @description Returns a raw (no leading "0x" or similar) hexadecimal
     * representation of the input with sign indicated by a leading "-"
     * character if negative and capital characters.
     * @param a SLI to represent.
     * @return Hexadecimal representation of SLI.
     * @function hex
     * @memberof verificatum.arithm.sli
     */
    var hex = function (a) {
        var s = "";
        if (a.sign < 0) {
            s = "-";
        }
        return s + li.hex(a.value);
    };

    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUG                                                           // DEBUG
    // DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES              // DEBUG
    // DEBUG                                                           // DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUG                                                           // DEBUG
    // DEBUG   INSECURErandom()                                        // DEBUG
    // DEBUG                                                           // DEBUG
    // DEBUG   Returns an array containing the given nominal number    // DEBUG
    // DEBUG   of random bits. The random bits are NOT SECURE FOR      // DEBUG
    // DEBUG   CRYPTOGRAPHIC USE.                                      // DEBUG
    // DEBUG                                                           // DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    var INSECURErandom = function (bitLength) {                        // DEBUG
        var x = li.INSECURErandom(bitLength);                          // DEBUG
        var sign = 1;                                                  // DEBUG
        if (li.iszero(x)) {                                            // DEBUG
            sign = 0;                                                  // DEBUG
        }                                                              // DEBUG
        return new SLI(sign, x);                                       // DEBUG
    };                                                                 // DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUG                                                  DEBUGDEBU// DEBUG
    // DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES     DEBUGDEBU// DEBUG
    // DEBUG                                                  DEBUGDEBU// DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG

    return {
        "SLI": SLI,
        "set": set,
        "copy": copy,
        "resize": resize,
        "normalize": normalize,
        "cmp": cmp,
        "equals": equals,
        "iszero": iszero,
        "shiftleft": shiftleft,
        "shiftright": shiftright,
        "add": add,
        "sub": sub,
        "mul": mul,
        "mul_number": mul_number,
        "square": square,
        "div_qr": div_qr,
        "mod": mod,
        "modinv": modinv,
        "egcd": egcd,
        "legendre": legendre,
        "modsqrt": modsqrt,
        "INSECURErandom": INSECURErandom,
        "hex": hex
    };
})();
