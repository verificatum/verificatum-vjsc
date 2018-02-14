
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
// ################### ec ###############################################
// ######################################################################

/**
 * Raw implementation of elliptic curves over prime order fields in
 * Jacobi coordinates, i.e., the affine coordinates (x, y) corresponds
 * to the projective coordinates (X * Z^2, Y * Z^3, Z).
 *
 * <p>
 *
 * Here elliptic curve points do not follow the object oriented
 * pattern with methods for adding, doubling, and multiplying. Instead
 * this is implemented in methods of the curve, or even plain
 * functions. This avoids allocations. Thus, the API is half-way
 * between different paradigms and the routines in this library are
 * not meant to be used directly.
 *
 * <p>
 *
 * The implementation is close to a verbatim port of the corresponding
 * code in the Verificatum Elliptic Curve library (VEC) written in
 * C. In particular, the addition and doubling routines have been
 * translated by search and replace.
 *
 * <p>
 *
 * All coordinates of elliptic curve points and temporary values are
 * stored using L = 2 * L' + 4 limbs, where L' is equal to the minimal
 * number of limbs needed to represent the order of the underlying
 * field.
 *
 * <p>
 *
 * The addition and doubling routines have full-multiplication depth 1
 * before every modular reduction. There may also be a few additions
 * or multiplication with integers bounded by 8. Such expressions fit
 * nicely into L limbs. After modular reduction L' words remain and
 * new expressions can be formed. This approach reduces the number of
 * modular reductions.
 *
 * @namespace ec
 * @memberof verificatum.arithm
 */
var ec = (function () {

    /**
     * @description Changes the representation of the point to canonical
     * coordinates, i.e. the unique representation where z is 1 and (x,y)
     * is the corresponding affine point. The exception is the point at
     * infinity which is left unchanged.
     * @param curve Elliptic curve.
     * @param A Point to affine.
     * @function affine
     * @memberof verificatum.arithm.ec
     */
    var affine_raw = (function () {

        // Temporary space for storing powers of inverses.
        var I = new sli.SLI();
        var II = new sli.SLI();
        var III = new sli.SLI();

        /** @lends */
        return function (curve, A) {

            // Resize temporary space if needed.
            if (I.length !== curve.length) {
                sli.resize(I, curve.length);
                sli.resize(II, curve.length);
                sli.resize(III, curve.length);
            }

            // We only consider points that map to affine points.
            if (!sli.iszero(A.z)) {

                sli.modinv(I, A.z, curve.modulus); // I = 1 / A.z

                sli.mul(II, I, I);                 // II = 1 / A.z^2
                sli.mod(II, II, curve.modulus);

                sli.mul(III, II, I);               // III = 1 / A.z^3
                sli.mod(III, III, curve.modulus);

                sli.mul(A.x, A.x, II);             // A.x = A.x / A.z^2
                sli.mod(A.x, A.x, curve.modulus);

                sli.mul(A.y, A.y, III);            // A.y = A.y / A.z^3
                sli.mod(A.y, A.y, curve.modulus);

                sli.set(A.z, 1);                   // A.z = 1
            }
        };
    })();

    /**
     * @description Sets A = B + C.
     * @param curve Elliptic curve.
     * @param A Holder of result.
     * @param B Point on curve.
     * @param C Point on curve.
     * @function jadd_generic
     * @memberof verificatum.arithm.ec
     */
    var jadd_generic = (function () {

        // Temporary variables with exactly the same number of limbs as
        // the modulus of the underlying field.
        var t1 = new sli.SLI();
        var t2 = new sli.SLI();
        var t3 = new sli.SLI();
        var U1 = new sli.SLI();
        var U2 = new sli.SLI();
        var S1 = new sli.SLI();
        var S2 = new sli.SLI();
        var H = new sli.SLI();
        var r = new sli.SLI();

        /** @lends */
        return function (curve, A, B, C) {

            var modulus = curve.modulus;
            var len = curve.length;
            if (t1.length !== len) {
                sli.resize(t1, len);
                sli.resize(t2, len);
                sli.resize(t3, len);
                sli.resize(U1, len);
                sli.resize(U2, len);
                sli.resize(S1, len);
                sli.resize(S2, len);
                sli.resize(H, len);
                sli.resize(r, len);
            }

            // B is point at infinity.
            if (sli.iszero(B.z)) {

                // C is also point at infinity.
                if (sli.iszero(C.z)) {
                    curve.setzero(A);
                    return;

                    // B is point at infinity and C is not.
                } else {
                    curve.set(A, C);
                    return;
                }

                // C is point at infinity and B is not.
            } else if (sli.iszero(C.z)) {
                curve.set(A, B);
                return;
            }

            // Compute powers of C.z.
            sli.mul(t1, C.z, C.z);                 // t1 = C.z^2
            sli.mod(t1, t1, modulus);
            sli.mul(S2, t1, C.z);                  // S2 = C.z^3
            sli.mod(S2, S2, modulus);

            // Compute powers of B.z
            sli.mul(t2, B.z, B.z);                 // t2 = B.z^2
            sli.mod(t2, t2, modulus);
            sli.mul(t3, t2, B.z);                  // t3 = B.z^3
            sli.mod(t3, t3, modulus);

            // U1 = B.x * C.z^2
            sli.mul(U1, B.x, t1);
            sli.mod(U1, U1, modulus);

            // U2 = C.x * B.z^2
            sli.mul(U2, C.x, t2);

            // S1 = B.y * C.z^3
            sli.mul(S1, B.y, S2);
            sli.mod(S1, S1, modulus);

            // S2 = C.y * B.z^3
            sli.mul(S2, C.y, t3);

            // H = U2 - U1
            sli.sub(H, U2, U1);
            sli.mod(H, H, modulus);

            // r = S2 - S1
            sli.sub(r, S2, S1);
            sli.mod(r, r, modulus);

            if (sli.iszero(H)) {

                if (sli.iszero(r)) {
                    curve.jdbl_raw(curve, A, B);
                    return;
                } else {
                    curve.setzero(A);
                    return;
                }
            }

            // Compute square of r
            sli.mul(t1, r, r);                     // t1 = r^2
            sli.mod(t1, t1, modulus);

            // Compute powers of H
            sli.mul(t2, H, H);                     // t2 = H^2
            sli.mod(t2, t2, modulus);
            sli.mul(t3, t2, H);                    // t3 = H^3
            sli.mod(t3, t3, modulus);

            // A.x = -H^3 - 2 * U1 * H^2 + r^2
            sli.sub(A.x, t1, t3);                  // A.x = r^2 - H^3

            sli.mul(t1, U1, t2);                   // t1 = 2*U1*H^2
            sli.shiftleft(t1, 1);                  // sli.mul_number(t1, t1, 2);
            sli.mod(t1, t1, modulus);

            sli.sub(A.x, A.x, t1);
            sli.mod(A.x, A.x, modulus);

            // A.y = -S1 * H^3 + r * (U1 * H^2 - A.x)
            sli.mul(t1, U1, t2);                   // t1 = r*(U1*H^2-A.x)
            sli.mod(t1, t1, modulus);
            sli.sub(t1, t1, A.x);
            sli.mul(t1, r, t1);
            sli.mod(t1, t1, modulus);

            sli.mul(t2, S1, t3);                   // t2 = S1*H^3
            sli.mod(t2, t2, modulus);

            sli.sub(A.y, t1, t2);
            sli.mod(A.y, A.y, modulus);

            // A.z = B.z * C.z * H
            sli.mul(A.z, B.z, C.z);
            sli.mod(A.z, A.z, modulus);
            sli.mul(A.z, A.z, H);
            sli.mod(A.z, A.z, modulus);
        };
    })();

    /**
     * @description Sets A = 2 * B.
     * <p>
     * References: Cohen/Miyaji/Ono Jacobi coordinates (1998).
     * @param curve Elliptic curve.
     * @param A Holder of result.
     * @param B Point on curve.
     * @function jdbl_generic
     * @memberof verificatum.arithm.ec
     */
    var jdbl_generic = (function () {

        // Temporary variables with exactly the same number of limbs as
        // the modulus of the underlying field.
        var t1 = new sli.SLI();
        var t2 = new sli.SLI();
        var t3 = new sli.SLI();
        var S = new sli.SLI();
        var M = new sli.SLI();
        var T = new sli.SLI();

        /** @lends */
        return function (curve, A, B) {

            var modulus = curve.modulus;
            var len = curve.length;

            if (t1.length !== len) {
                sli.resize(t1, len);
                sli.resize(t2, len);
                sli.resize(t3, len);
                sli.resize(S, len);
                sli.resize(M, len);
                sli.resize(T, len);
            }

            // B is point at infinity or point which is its own inverse.
            if (sli.iszero(B.z) || sli.iszero(B.y)) {
                curve.setzero(A);
                return;
            }

            // S = 4*B.x*B.y^2
            sli.mul(S, B.y, B.y);
            sli.mod(S, S, modulus);
            sli.mul(S, S, B.x);
            sli.shiftleft(S, 2);                   // sli.mul_number(S, S, 4);
            sli.mod(S, S, modulus);

            // B.z squared
            sli.mul(t2, B.z, B.z);                 // t2 = B.z^2
            sli.mod(t2, t2, modulus);

            // M = 3*B.x^2+a*B.z^4
            sli.mul(t1, B.x, B.x);                 // t1 = 3*B.x^2
            sli.mod(t1, t1, modulus);
            sli.mul_number(t1, t1, 3);
            sli.mod(t1, t1, modulus);

            sli.mul(t3, t2, t2);                   // t3 = a*B.z^4
            sli.mod(t3, t3, modulus);
            sli.mul(t3, t3, curve.a);
            sli.mod(t3, t3, modulus);

            sli.add(M, t1, t3);
            sli.mod(M, M, modulus);

            // T = M^2-2*S
            sli.mul(T, M, M);
            sli.set(t2, S);                        // sli.mul_number(t2, S, 2);
            sli.shiftleft(t2, 1);
            sli.sub(T, T, t2);
            sli.mod(T, T, modulus);

            // A.x = T
            sli.set(A.x, T);

            // A.y = -8*B.y^4+M*(S-T)
            sli.sub(t1, S, T);                     // t1 = M*(S-T)
            sli.mul(t1, t1, M);
            sli.mod(t1, t1, modulus);

            sli.mul(t2, B.y, B.y);                 // t2 = 8*B.y^4
            sli.mod(t2, t2, modulus);
            sli.mul(t2, t2, t2);
            sli.mod(t2, t2, modulus);
            sli.shiftleft(t2, 3);                  // sli.mul_number(t2, t2, 8);
            sli.mod(t2, t2, modulus);

            sli.sub(t1, t1, t2);

            // A.z = 2*B.y*B.z
            sli.mul(t2, B.y, B.z);
            sli.shiftleft(t2, 1);                  // sli.mul_number(t2, t2, 2);

            sli.mod(A.y, t1, modulus);
            sli.mod(A.z, t2, modulus);
        };
    })();

    /**
     * @description Sets A = 2 * B.
     *
     * <p>
     *
     * ASSUMES: a = -3 for the curve.
     *
     * <p>
     *
     * References: Bernstein Jacobi coordinates (2001).
     *
     * @param curve Elliptic curve.
     * @param A Holder of result.
     * @param B Point on curve.
     * @function jdbl_a_eq_neg3
     * @memberof verificatum.arithm.ec
     */
    var jdbl_a_eq_neg3 = (function () {

        // Temporary variables with exactly the same number of limbs as
        // the modulus of the underlying field.
        var t1 = new sli.SLI();
        var t2 = new sli.SLI();
        var t3 = new sli.SLI();
        var alpha = new sli.SLI();
        var beta = new sli.SLI();
        var gamma = new sli.SLI();
        var delta = new sli.SLI();

        /** @lends */
        return function (curve, A, B) {

            var modulus = curve.modulus;
            var len = curve.length;
            if (t1.length !== len) {
                sli.resize(t1, len);
                sli.resize(t2, len);
                sli.resize(t3, len);
                sli.resize(alpha, len);
                sli.resize(beta, len);
                sli.resize(gamma, len);
                sli.resize(delta, len);
            }

            // B is point at infinity or point which is its own negative.
            if (sli.iszero(B.z) || sli.iszero(B.y)) {
                curve.setzero(A);
                return;
            }

            // delta = B.z^2
            sli.mul(delta, B.z, B.z);
            sli.mod(delta, delta, modulus);

            // gamma = B.y^2
            sli.mul(gamma, B.y, B.y);
            sli.mod(gamma, gamma, modulus);

            // beta = B.x * gamma
            sli.mul(beta, B.x, gamma);
            sli.mod(beta, beta, modulus);

            // alpha = 3 * (B.x - delta) * (B.x + delta)
            sli.sub(t1, B.x, delta);
            sli.add(t2, B.x, delta);
            sli.mul_number(t1, t1, 3);
            sli.mul(alpha, t1, t2);
            sli.mod(alpha, alpha, modulus);

            // A.x = alpha^2 - 8 * beta
            sli.mul(t1, alpha, alpha);
            sli.set(t2, beta);                  // sli.mul_number(t2, beta, 8);
            sli.shiftleft(t2, 3);
            sli.sub(A.x, t1, t2);
            sli.mod(A.x, A.x, modulus);

            // A.z = (B.y + B.z)^2 - gamma - delta
            sli.add(t1, B.y, B.z);
            sli.mul(t1, t1, t1);
            sli.sub(t1, t1, gamma);
            sli.sub(t1, t1, delta);
            sli.mod(A.z, t1, modulus);

            // A.y = alpha * (4 * beta - A.x) - 8 * gamma^2
            sli.set(t1, beta);                  // sli.mul_number(t1, beta, 4);
            sli.shiftleft(t1, 2);
            sli.sub(t1, t1, A.x);
            sli.mul(t1, t1, alpha);

            sli.mul(t2, gamma, gamma);
            sli.shiftleft(t2, 3);               // sli.mul_number(t2, t2, 8);

            sli.sub(A.y, t1, t2);
            sli.mod(A.y, A.y, modulus);
        };
    })();

    /**
     * @description Sets A = e * B.
     * <p>
     * @param curve Elliptic curve.
     * @param A Holder of result.
     * @param B Point on curve.
     * @param e Scalar.
     * @function jmul_naive
     * @memberof verificatum.arithm.ec
     */
    var jmul_naive = function (curve, A, B, e) {

        // Index of most significant bit.
        var n = li.msbit(e.value);

        curve.setzero(A);

        // Iterate through the remaining bits of e starting from the most
        // significant bit.
        for (var i = n; i >= 0; i--) {

            // A = 2 * A
            curve.jdbl(A, A);

            if (li.getbit(e.value, i) === 1) {

                // A = A + B
                curve.jadd(A, A, B);
            }
        }
    };

    /**
     * @description Raw container class for elliptic curves.
     *
     * <p>
     *
     * ASSUMES: 0 <= a, b, gx, gy < modulus, n > 0, and x^3 + b * x + a
     * (mod modulus) is a non-singular curve of order n.
     *
     * @param modulus Modulus for underlying field.
     * @param a First coefficient for curve of Weierstrass normal form.
     * @param b Second coefficientfor curve of Weierstrass normal form.
     * @param n Order of elliptic curve.
     * @class
     * @memberof verificatum.arithm.ec
     */
    function EC(modulus, a, b) {

        this.modulus = modulus;

        // For simplicity we use a fixed length for all variables. This
        // allows computing a single product and a few additions and
        // subtractions as needed below.
        this.length = 2 * this.modulus.value.length + 4;

        this.a = a;
        this.b = b;

        // Use faster doubling algorithm if a = modulus - 3.
        var three = new sli.SLI(1, [3]);
        var t = new sli.SLI(modulus.length + 1);
        sli.add(t, this.a, three);

        if (sli.equals(this.modulus, t)) {
            this.jdbl_raw = jdbl_a_eq_neg3;
        } else {
            this.jdbl_raw = jdbl_generic;
        }
    };

    /**
     * @description Container class for raw elliptic curve points.
     * @param len Number of limbs to be used to represent the coordinates
     * of the point.
     * @param x x-coordinate of point on the curve.
     * @param y y-coordinate of point on the curve.
     * @param z z-coordinate of point on the curve.
     * @class ECP
     * @memberof verificatum.arithm.ec
     */
    function ECP(len, x, y, z) {
        if (typeof x === "undefined") {
            this.x = new sli.SLI(len);
            this.y = new sli.SLI(len);
            this.z = new sli.SLI(len);
        } else {
            this.x = sli.copy(x, len);
            this.y = sli.copy(y, len);
            this.z = sli.copy(z, len);
        }
    };

    /**
     * @description Changes the representation of the point to canonical
     * coordinates, i.e. the unique representation where z is 1 and (x,y)
     * is the corresponding affine point. The exception is the point at
     * infinity which is left unchanged.
     * @param A Point to affine.
     * @method
     */
    EC.prototype.affine = function (A) {
        affine_raw(this, A);
    };

    /**
     * @description Compares A and B.
     * @param A Left point on curve.
     * @param B Right point on curve.
     * @return true or false depending on if A and B represent the same
     * point on the curve or not.
     * @method
     */
    EC.prototype.equals = function (A, B) {
        this.affine(A);
        this.affine(B);
        return sli.cmp(A.x, B.x) === 0 &&
            sli.cmp(A.y, B.y) === 0 &&
            sli.cmp(A.z, B.z) === 0;
    };

    /**
     * @description Sets A = B.
     * @param A Holder of result.
     * @param B Point on curve.
     * @method
     */
    EC.prototype.set = function (A, B) {
        sli.set(A.x, B.x);
        sli.set(A.y, B.y);
        sli.set(A.z, B.z);
    };

    /**
     * @description Sets A = O, where O is the unit element of the
     * elliptic curve.
     * @param A Holder of result.
     * @method
     */
    EC.prototype.setzero = function (A) {
        sli.set(A.x, 0);
        sli.set(A.y, 1);
        sli.set(A.z, 0);
    };

    /**
     * @description Sets A = -B.
     * @param A Holder of result.
     * @param B Point on curve.
     * @method
     */
    EC.prototype.neg = function (A, B) {

        // If B is the unit element, or if it is not, but it is its own
        // negative, then we set A = B.
        if (sli.iszero(B.z) || sli.iszero(B.y)) {
            this.set(A, B);

            // Otherwise we mirror along the y-axis.
        } else {
            sli.set(A.x, B.x);
            sli.sub(A.y, this.modulus, B.y);
            sli.set(A.z, B.z);
        }
    };

    /**
     * @description Sets A = B + C.
     * @param A Holder of result.
     * @param B Point on curve.
     * @param C Point on curve.
     * @method
     */
    EC.prototype.jadd = function (A, B, C) {
        jadd_generic(this, A, B, C);
    };

    /**
     * @description Sets A = 2 * B.
     * @param A Holder of result.
     * @param B Point on curve.
     * @method
     */
    EC.prototype.jdbl = function (A, B) {
        this.jdbl_raw(this, A, B);
    };

    /**
     * @description Sets A = e * B.
     * @param A Holder of result.
     * @param B Point on curve.
     * @param e Scalar.
     * @method
     */
    EC.prototype.jmul = function (A, B, e) {
        jmul_naive(this, A, B, e);
    };

    return {
        "EC": EC,
        "ECP": ECP
    };
})();
