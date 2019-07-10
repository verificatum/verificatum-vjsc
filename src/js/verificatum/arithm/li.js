
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
// ################### li ###############################################
// ######################################################################

/**
 * @description Utility classes and functions.
 *
 * <p>
 *
 * Provides the core large integer arithmetic routines needed to
 * implement multiplicative groups and elliptic curve groups over
 * prime order fields. No additional functionality is provided.
 * Although the main goal of this module is to be well-documented and
 * clearly structured with proper encapsulation and without hidden
 * assumptions, this is quite hard in a few routines.
 *
 * <p>
 *
 * WARNING! This module must be used with care due to the assumptions
 * made by routines on inputs, but these assumptions are stated
 * explicitly for each function, so the code is easy to follow.
 *
 * <p>
 *
 * Integers are represented as arrays of numbers constrained to
 * WORDSIZE bits, where WORDSIZE is any even number between 4 and 30
 * and there are hardcoded constants derived from this when the script
 * is generated, so do not attempt to change the wordsize in the
 * generated code. These wordsizes are natural since JavaScript only
 * allows bit operations on 32-bit signed integers. To see this, note
 * that although we can do arithmetic on floating point numbers, e.g.,
 * by setting WORDSIZE = 24 we could do multiplications directly, it
 * is expensive to recover parts of the result. Bit operations on
 * 32-bit integers are provided in Javascript, but they are
 * implemented on top of the native "number" datatype, i.e., numbers
 * are cast to 32-bit signed integers, the bit operation is applied,
 * and the result is cast back to a "number".
 *
 * <p>
 *
 * Using small wordsizes exposes certain types of arithmetic bugs, so
 * providing this is not merely for educational purposes, it is also
 * to lower the risk of structural bugs.
 *
 * <p>
 *
 * Functions are only implemented for unsigned integers and when
 * called from external functions they assume that any result
 * parameter is of a given length. All arithmetic functions guarantee
 * that any leading unused words are set to zero.
 *
 * <p>
 *
 * A "limb" is an element of an array that may or may not store any
 * single-precision integer. A word is a limb containing data, which
 * may be zero if there are limbs at higher indices holding
 * data. Thus, the number of limbs is the length of an array and the
 * number of words is the index of the most significant word in the
 * array plus one.
 *
 * <p>
 *
 * The workhorse routine is muladd_loop() which is generated for a
 * given fixed wordsize. This routine determines the speed of
 * multiplication and squaring. To a large extent it also determines
 * the speed of division, but here div3by2() also plays an important
 * role. These routines are generated from M4 macro code to allow
 * using hard coded wordsize dependent constants for increased
 * speed. The square_naive() routine also contains some generated
 * code.
 *
 * <p>
 *
 * JavaScript is inherently difficult to optimize, since the
 * JavaScript engines are moving targets, but it seems that the
 * built-in arrays in Javascript are faster than the new typed arrays
 * if they are handled properly. A first version of the library was
 * based on Uint32Array for which, e.g., allocation of a fixed-size
 * array is slower than a builtin array.
 *
 * <p>
 *
 * One notable observation is that it sometimes makes sense to inform
 * the interpreter that a JavaScript "number" / float is really a
 * 32-bit integer by saying, e.g., (x | 0) even if we are guaranteed
 * that x is a 32-bit integer. This is important when accessing
 * elements from arrays and it seems to prevent the interpreter from
 * converting to and from floats.
 *
 * <p>
 *
 * We avoid dynamic memory allocation almost entirely by keeping
 * scratch space as static variables of the functions. This is
 * implemented using immediate function evaluation in JavaScript, but
 * it is encapsulated to reduce complexity, i.e., calling functions
 * remain unaware of this. This approach works well in our
 * applications, since higher level routines work with integers of
 * fixed bit length;
 *
 * <p>
 *
 * <a href="http://cacr.uwaterloo.ca/hac">Handbook of Cryptography
 * (HAC), Alfred J. Menezes, Paul C. van Oorschot and Scott
 * A. Vanstone</a> gives a straightforward introduction to the basic
 * algorithms used and we try to follow their notation for easy
 * reference. Division exploits the techniques of <a
 * href="https://gmplib.org/~tege/division-paper.pdf">Improved
 * division by invariant integers, Niels Moller and Torbjorn Granlund
 * (MG)</a>. This is needed to implement div3by2() efficiently.
 *
 * <p>
 *
 * <table style="text-align: left;">
 * <tr><th>Reference        </th><th> Operation</th><th> Comment</th></tr>
 * <tr><td>HAC 14.7.        </td><td> Addition</td><td></td></tr>
 * <tr><td>HAC 14.9.        </td><td> Subtraction</td><td></td></tr>
 * <tr><td>HAC 14.12.       </td><td> Multiplication</td><td> Uses Karatsuba.</td></tr>
 * <tr><td>HAC 14.16.       </td><td> Squaring</td><td> Uses Karatsuba.</td></tr>
 * <tr><td>HAC 14.20 and MG.</td><td> Division.</td><td> Uses reciprocals for invariant moduli.</td></tr>
 * <tr><td>HAC 14.83.       </td><td> Modular exponentiation</td><td> Left-to-right k-ary.</td></tr>
 * </table>
 *
 * @namespace li
 * @memberof verificatum.arithm
 */
var li = (function () {

// ################### Constants ########################################

// Wordsize.
var WORDSIZE = M4_WORDSIZE;

// Size threshold for using Karatsuba in multiplication.
var KARATSUBA_MUL_THRESHOLD = 24;

// Size threshold for using Karatsuba in squaring.
var KARATSUBA_SQR_THRESHOLD = 35;

// Threshold for relative difference in size for using Karatsuba in
// multiplication.
var KARATSUBA_RELATIVE = 0.8;

/**
 * @description Sets x = 0.
 * @param x Array to modify.
 * @function setzero
 * @memberof verificatum.arithm.li
 */
var setzero = function (x) {
    for (var i = 0; i < x.length; i++) {
        x[i] = 0;
    }
};

/**
 * @description Sets w = x and truncates or pads with zeros as needed
 * depending on the number of limbs in w. The x parameter can be an
 * array or a "number" < 2^M4_WORDSIZE.
 * @param w Array or "number" holding result.
 * @param x Array holding value.
 * @function set
 * @memberof verificatum.arithm.li
 */
var set = function (w, x) {
    if (typeof x === "number") {
        setzero(w);
        w[0] = x;
    } else {
        var i = 0;
        while (i < Math.min(w.length, x.length)) {
            w[i] = x[i];
            i++;
        }
        while (i < w.length) {
            w[i] = 0;
            i++;
        }
    }
};

/**
 * @description Allocates new array of the given length where all
 * elements are zero.
 * @param len Length of array.
 * @return Array of the given length where all elements are zero.
 * @function newarray
 * @memberof verificatum.arithm.li
 */
var newarray = function (len) {
    var x = [];
    x.length = len;
    setzero(x);
    return x;
};

/**
 * @description Returns a copy of the given array.
 * @param x Original array.
 * @param len Maximal length of copy.
 * @return Copy of original array.
 * @function copyarray
 * @memberof verificatum.arithm.li
 */
var copyarray = function (x, len) {
    if (typeof len === "undefined") {
        len = 0;
    }
    var w = newarray(Math.max(x.length, len));
    set(w, x);
    return w;
};

/**
 * @description Resizes the array to the given number of limbs,
 * either by truncating or by adding leading zero words.
 * @param x Original array.
 * @param len New length.
 * @function resize
 * @memberof verificatum.arithm.li
 */
var resize = function (x, len) {
    var xlen = x.length;
    x.length = len;
    if (len > xlen) {
        for (var i = xlen; i < len; i++) {
            x[i] = 0;
        }
    }
};

/**
 * @description Truncates the input to the shortest possible array
 * that represents the same absolute value in two's complement, i.e.,
 * there is always a leading zero bit.
 * @param x Array to truncate.
 * @param mask_top Mask for a given wordsize with only most
 * significant bit set.
 * @function normalize
 * @memberof verificatum.arithm.li
 */
var normalize = function (x, mask_top) {

    if (typeof mask_top === "undefined") {
        mask_top = M4_MASK_MSB;
    }

    var l = x.length - 1;

    // There may be zeros to truncate.
    if (x[l] === 0) {

        // Find index of most significant non-zero word.
        while (l > 0 && x[l] === 0) {
            l--;
        }

        // If most significant bit of this word is set, then we keep a
        // leading zero word.
        if ((x[l] & mask_top) !== 0) {
            l++;
        }
        x.length = l + 1;

        // We need to add a zero word to turn it into a positive integer
        // in two's complement.
    } else if ((x[l] & mask_top) !== 0) {

        x.length++;
        x[x.length - 1] = 0;
    }
};

/**
 * @description Sets x = 1.
 * @param x Array to modify.
 * @function setone
 * @memberof verificatum.arithm.li
 */
var setone = function (x) {
    setzero(x);
    x[0] = 1;
};

/**
 * @description Returns the index of the most significant bit in x.
 * @param x Array containing bit.
 * @return An index i such that 0 <= i < x.length * M4_WORDSIZE.
 * @function msbit
 * @memberof verificatum.arithm.li
 */
var msbit = function (x) {

    for (var i = x.length - 1; i >= 0; i--) {

        // Find index of most significant word.
        if (x[i] !== 0) {

            // Find index of most significant bit within the most
            // significant word.
            var msbit = (i + 1) * M4_WORDSIZE - 1;

            for (var mask = M4_MASK_MSB; mask !== 0; mask >>>= 1) {

                if ((x[i] & mask) === 0) {
                    msbit--;
                } else {
                    return msbit;
                }
            }
        }
    }
    return 0;
};

/**
 * @description Returns the lowest index of a set bit in the input or
 * zero if the input is zero.
 * @param Array containing bit.
 * @return An index i such that 0 <= i < x.length * M4_WORDSIZE.
 * @function lsbit
 * @memberof verificatum.arithm.li
 */
var lsbit = function (x) {
    var i = 0;
    while (i < x.length && x[i] === 0) {
        i++;
    }

    if (i === x.length) {

        return 0;

    } else {

        var j = 0;
        while ((x[i] >>> j & M4_MASK_LSB) === 0) {
            j++;
        }

        return i * M4_WORDSIZE + j;
    }
};

/**
 * @description Returns the array index of the most significant word.
 * @param x Array containing word.
 * @return An index i such that 0 <= i < x.length.
 * @function msword
 * @memberof verificatum.arithm.li
 */
var msword = function (x) {
    for (var i = x.length - 1; i > 0; i--) {
        if (x[i] !== 0) {
            return i;
        }
    }
    return 0;
};

/**
 * @description Returns 1 or 0 depending on if the given bit is set or
 * not. Accessing a bit outside the number of limbs returns zero.
 * @param x Array containing bit.
 * @param index Index of bit.
 * @return Bit as a "number" at the given position.
 * @function getbit
 * @memberof verificatum.arithm.li
 */
var getbit = function (x, index) {
    var wordIndex = Math.floor(index / M4_WORDSIZE);
    var bitIndex = index % M4_WORDSIZE;

    if (wordIndex >= x.length) {
        return 0;
    }

    if ((x[wordIndex] & 1 << bitIndex) === 0) {
        return 0;
    } else {
        return 1;
    }
};

/**
 * @description Checks if the input represents the zero integer.
 * @param x Array to inspect.
 * @return True or false depending on if x represents zero or not.
 * @function iszero
 * @memberof verificatum.arithm.li
 */
var iszero = function (x) {
    for (var i = 0; i < x.length; i++) {
        if (x[i] !== 0) {
            return false;
        }
    }
    return true;
};

/**
 * @description Returns -1, 0, or 1 depending on if x < y, x == y, or
 * x > y.
 *
 * <p>
 *
 * ASSUMES: x and y are positive.
 *
 * @param x Left array.
 * @param x Right array.
 * @return Sign of comparison relation.
 * @function cmp
 * @memberof verificatum.arithm.li
 */
var cmp = function (x, y) {

    // Make sure that x has at least as many words as y does, and
    // remember if we swapped them to correct the sign at the end.
    var sign = 1;
    if (x.length < y.length) {
        var t = x;
        x = y;
        y = t;
        sign = -1;
    }

    var i = x.length - 1;

    while (i >= y.length) {
        if (x[i] === 0) {
            i--;
        } else {
            return sign;
        }
    }
    while (i >= 0) {
        if (x[i] > y[i]) {
            return sign;
        } else if (x[i] < y[i]) {
            return -sign;
        }
        i--;
    }
    return 0;
};

/**
 * @description Shifts the given number of bits within the array,
 * i.e., the allocated space is not expanded.
 *
 * <p>
 *
 * ASSUMES: offset >= 0.
 *
 * @param x Array to be shifted.
 * @param offset Number of bit positions to shift.
 * @function shiftleft
 * @memberof verificatum.arithm.li
 */
var shiftleft = function (x, offset) {

    // No shifting.
    if (offset === 0) {
        return;
    }

    // Too much shifting.
    if (offset >= x.length * M4_WORDSIZE) {
        setzero(x);
        return;
    }

    // Left shift words.
    var wordOffset = Math.floor(offset / M4_WORDSIZE);
    if (wordOffset > 0) {

        var j = x.length - 1;
        while (j >= wordOffset) {
            x[j] = x[j - wordOffset];
            j--;
        }
        while (j >= 0) {
            x[j] = 0;
            j--;
        }
    }

    // Left shift bits within words.
    var bitOffset = offset % M4_WORDSIZE;
    var negBitOffset = M4_WORDSIZE - bitOffset;

    if (bitOffset !== 0) {
        for (var i = x.length - 1; i > 0; i--) {
            var left = x[i] << bitOffset & M4_MASK_ALL;
            var right = x[i - 1] >>> negBitOffset;
            x[i] = left | right;
        }
        x[0] = x[0] << bitOffset & M4_MASK_ALL;
    }
};

/**
 * @description Shifts the given number of bits to the right within
 * the allocated space, i.e., the space is not reduced.
 *
 * <p>
 *
 * ASSUMES: offset >= 0.
 *
 * @param x Array to be shifted.
 * @param offset Number of bit positions to shift.
 * @function shiftright
 * @memberof verificatum.arithm.li
 */
var shiftright = function (x, offset) {

    // No shifting.
    if (offset === 0) {
        return;
    }

    // Too much shifting.
    if (offset >= x.length * M4_WORDSIZE) {
        setzero(x);
        return;
    }

    // Right shift words.
    var wordOffset = Math.floor(offset / M4_WORDSIZE);
    if (wordOffset > 0) {

        var j = 0;
        while (j < x.length - wordOffset) {
            x[j] = x[j + wordOffset];
            j++;
        }
        while (j < x.length) {
            x[j] = 0;
            j++;
        }
    }

    // Right shift bits within words.
    var bitOffset = offset % M4_WORDSIZE;
    var negBitOffset = M4_WORDSIZE - bitOffset;

    if (bitOffset !== 0) {
        for (var i = 0; i < x.length - 1; i++) {
            var left = x[i] >>> bitOffset;
            var right = x[i + 1] << negBitOffset & M4_MASK_ALL;
            x[i] = left | right;
        }
        x[x.length - 1] = x[x.length - 1] >>> bitOffset;
    }
};

/**
 * @description Sets w = x + y.
 *
 * <p>
 *
 * ASSUMES: x and y are positive and have B and B' bits and w can
 * store (B + B' + 1) bits. A natural choice in general is to let w
 * have (L + L' + 1) limbs if x and y have L and L' limbs, but the
 * number of limbs can be arbitrary.
 *
 * <p>
 *
 * References: HAC 14.7.
 *
 * @param w Array holding the result.
 * @param x Left term.
 * @param y Right term.
 * @function add
 * @memberof verificatum.arithm.li
 */
var add = function (w, x, y) {
    var tmp;
    var c = 0;

    // Make sure that x is at least as long as y.
    if (x.length < y.length) {
        var t = x;
        x = y;
        y = t;
    }

    // Add words of x and y with carry.
    var i = 0;
    var len = Math.min(w.length, y.length);
    while (i < len) {
        tmp = x[i] + y[i] + c;

        w[i] = tmp & M4_MASK_ALL;
        c = tmp >> M4_WORDSIZE;
        i++;
    }

    // Add x and carry.
    len = Math.min(w.length, x.length);
    while (i < len) {
        tmp = x[i] + c;

        w[i] = tmp & M4_MASK_ALL;
        c = tmp >> M4_WORDSIZE;
        i++;
    }

    // Set carry and clear the rest.
    if (i < w.length) {
        w[i] = c;
        i++;
    }
    while (i < w.length) {
        w[i] = 0;
        i++;
    }
};

/* jshint -W126 */ /* Ignore singleGroups. */
/* eslint-disable no-extra-parens */
/**
 * @description Sets w to the negative of x in two's complement
 * representation using L * M4_WORDSIZE bits, where L is the number of
 * limbs in w.
 *
 * <p>
 *
 * ASSUMES: w has at least as many limbs as x.
 *
 * @param w Array holding the result.
 * @param x Integer.
 * @function neg
 * @memberof verificatum.arithm.li
 */
var neg = function (w, x) {
    var i;
    var c;
    var tmp;

    c = 1;
    i = 0;
    while (i < x.length) {
    tmp = (x[i] ^ M4_MASK_ALL) + c;
    w[i] = tmp & M4_MASK_ALL;
    c = (tmp >> M4_WORDSIZE) & M4_MASK_ALL;
    i++;
    }
    while (i < w.length) {
        tmp = M4_MASK_ALL + c;
        w[i] = tmp & M4_MASK_ALL;
        c = (tmp >> M4_WORDSIZE) & M4_MASK_ALL;
        i++;
    }
};
/* jshint +W126 */ /* Stop ignoring singleGroups. */
/* eslint-enable no-extra-parens */

/**
 * @description Sets w = x - y if x >= y and otherwise it simply
 * propagates -1, i.e., M4_MASK_ALL, through the remaining words of
 * w.
 *
 * <p>
 *
 * ASSUMES: for normal use x >= y, and x and y have B and B' bits and
 * w can store B bits. A natural choice is to use L >= L' limbs for x
 * and y respectively and L limbs for w, but the number of limbs can
 * be arbitrary.
 *
 * <p>
 *
 * References: HAC 14.9.
 *
 * @param w Array holding the result.
 * @param x Left term.
 * @param y Right term.
 * @return Finally carry.
 * @function sub
 * @memberof verificatum.arithm.li
 */
var sub = function (w, x, y) {
    var tmp;
    var c = 0;

    // Subtract words of x and y with carry.
    var len = Math.min(w.length, x.length, y.length);

    var i = 0;
    while (i < len) {
        tmp = x[i] - y[i] + c;
        w[i] = tmp & M4_MASK_ALL;
        c = tmp >> M4_WORDSIZE;
        i++;
    }

    // Propagate carry along with one of x and y.
    if (x.length > y.length) {
        len = Math.min(w.length, x.length);
        while (i < len) {
            tmp = x[i] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >> M4_WORDSIZE;
            i++;
        }
    } else {
        len = Math.min(w.length, y.length);
        while (i < len) {
            tmp = -y[i] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >> M4_WORDSIZE;
            i++;
        }
    }

    // Propagate carry.
    while (i < w.length) {
        w[i] = c & M4_MASK_ALL;
        c = tmp >> M4_WORDSIZE;
        i++;
    }
    return c;
};

/* jshint -W126 */ /* Ignore singleGroups. */
/* eslint-disable no-extra-parens */
/* eslint-disable space-in-parens */
/* eslint-disable semi-spacing */
/**
 * @description Specialized implementation of muladd_loop() for
 * M4_WORDSIZE-bit words. This is essentially a naive
 * double-precision multiplication computation done in a loop. This
 * code is quite sensitive to replacing the constants with variables,
 * which explains why it is generated from source with macros. Using
 * two's complement for temporary values this can be used as a
 * "mulsub_loop" as well.
 *
 * <p>
 *
 * Computes (pseudo-code) that due to limited precision and 32-bit
 * bound bit operations does not work in JavaScript:
 *
 * <pre>
 * for (var j = start; j < end; j++) {
 *     tmp = x[j] * Y + w[i + j] + c;
 *     w[i + j] = tmp & M4_MASK_ALL;
 *     c = tmp >>> M4_WORDSIZE;
 * }
 * return c;
 * </pre>
 *
 * <p>
 *
 * Note that if Y < 2^(M4_WORDSIZE + 1), then the output carry c is
 * only guaranteed to be smaller than 2^(M4_WORDSIZE + 1), which does
 * not fit into a word.
 *
 * <p>
 *
 * ASSUMES: Y < 2^(M4_WORDSIZE + 1).
 *
 * @param w Array holding additive terms as input and the output.
 * @param x Array to be scaled.
 * @param start Start index into x.
 * @param end End index into x.
 * @param Y Scalar.
 * @param i Index into w.
 * @param c Input carry.
 * @return Finally carry.
 * @function muladd_loop
 * @memberof verificatum.arithm.li
 */
var muladd_loop = function (w, x, start, end, Y, i, c) {

    // Temporary variables in muladd.
    var hx;
    var lx;
    var cross;

    // Extract upper and lower halves of Y.
    var hy = M4_HIGH(Y);
    var ly = M4_LOW(Y);

    // This implies:
    // hy < 2^(M4_HALF_WORDSIZE + 1)
    // ly < 2^M4_HALF_WORDSIZE

    // The invariant of the loop is c < 2^(M4_WORDSIZE + 1).
    for (var j = start; j < end; j++) {

        M4_WORD_MULADD2(w[j + i],x[j],hy,ly,c,hx,lx,cross);
    }

    // This is a (M4_WORDSIZE + 1)-bit word when Y is.
    return c;
};

/**
 * @description Sets w = x * y, where w has two limbs and x and y are
 * words. This is specialized similarly to muladd_loop and generated
 * using the same macro.
 *
 * @param w Destination long.
 * @param x Single word factor.
 * @param y Single word factor.
 *
 * @function word_mul
 * @memberof verificatum.arithm.li
 */
var word_mul = function (w, x, y) {
    var hx;
    var lx;
    var cross;
    var hy;
    var ly;

    // Clear the result, since we are muladding.
    w[0] = 0;
    w[1] = 0;

    // Extract upper and lower halves of y.
    hy = M4_HIGH(y);
    ly = M4_LOW(y);

    M4_WORD_MULADD2(w[0],x,hy,ly,w[1],hx,lx,cross);
};
/* jshint +W126 */ /* Stop ignoring singleGroups */
/* eslint-enable no-extra-parens */
/* eslint-enable space-in-parens */
/* eslint-enable semi-spacing */

/* jshint -W126 */ /* Ignore singleGroups */
/* eslint-disable no-extra-parens */
/**
 * @description Sets w = x * x.
 *
 * <p>
 *
 * ASSUMES: x is non-negative with L and L' limbs respectively, and
 * that w has at least L + L' limbs.
 *
 * <p>
 *
 * References: HAC 14.16.
 *
 * @param w Array holding the result.
 * @param x Factor.
 * @function square_naive
 * @memberof verificatum.arithm.li
 */
var square_naive = function (w, x) {
    var n = msword(x) + 1;
    var c;
    var sc = 0;

    setzero(w);

    var i = 0;
    while (i < n) {

        // This computes
        // (c, w[2 * i]) = w[2 * i] + x[i] * x[i],
        // where the result is interpreted as a pair of integers of
        // sizes (M4_WORDSIZE + 1, M4_WORDSIZE):

        var l = x[i] & M4_HALF_MASK_ALL;
        var h = x[i] >>> M4_HALF_WORDSIZE;
        var cross = l * h << 1;

        // This implies:
        // l, h < 2^M4_HALF_WORDSIZE
        // cross < 2^(M4_WORDSIZE + 1)

        l = (w[i << 1] | 0) + l * l +
            ((cross & M4_HALF_MASK_ALL) << M4_HALF_WORDSIZE);

        // This implies, so we can safely use bit operators on l;
        // l < 2^(M4_WORDSIZE + 2)

        c = ((l >>> M4_WORDSIZE) + (cross >>> M4_HALF_WORDSIZE) + h * h) | 0;
        w[i << 1] = l & M4_MASK_ALL;

        // This implies, which is a requirement for the loop.
        // c < 2^(M4_WORDSIZE + 1)
        //
        // The standard way to do this would be to simply allow each
        // w[i + n] to intermittently hold a WORDSIZE + 1 bit integer
        // (or overflow register), but for 30-bit words this causes
        // overflow in muladd_loop.
        sc = muladd_loop(w, x, i + 1, n, x[i] << 1, i, c) + sc;
        w[i + n] = sc & M4_MASK_ALL;
        sc >>>= M4_WORDSIZE;

        i++;
    }
};
/* jshint +W126 */ /* Stop ignoring singleGroups */
/* eslint-enable no-extra-parens */

/**
 * @description Splits x into two parts l and h of equal and
 * predetermined size, i.e., the lengths of the lists l and h
 * determines how x is split.
 * @param l Array holding most significant words of x.
 * @param h Array holding most significant words of x.
 * @param x Original array.
 * @function karatsuba_split
 * @memberof verificatum.arithm.li
 */
var karatsuba_split = function (l, h, x) {

    var m = Math.min(l.length, x.length);
    var i = 0;

    while (i < m) {
        l[i] = x[i];
        i++;
    }
    while (i < l.length) {
        l[i] = 0;
        i++;
    }
    while (i < x.length) {
        h[i - l.length] = x[i];
        i++;
    }
    i -= l.length;
    while (i < l.length) {
        h[i] = 0;
        i++;
    }
};

/* jshint -W074 */ /* Ignore maxcomplexity. */
/**
 * @description Sets w = x * x. The depth parameter determines the
 * recursive depth of function calls and must be less than 3.
 *
 * <p>
 *
 * ASSUMES: x is non-negative and has L limbs and w has at least 2 * L
 * limbs.
 *
 * <p>
 *
 * References: HAC <sectionsign>14.2,
 * https://en.wikipedia.org/wiki/Karatsuba_algorithm
 *
 * @param w Array holding the result.
 * @param x Factor.
 * @param depth Recursion depth of the Karatsuba algorithm.
 * @function square_karatsuba
 * @memberof verificatum.arithm.li
 */
var square_karatsuba = (function () {

    // Scratch space indexed by depth. These arrays are resized as
    // needed in each call. In typical cryptographic applications big
    // integers have the same size, so no resize takes place.
    var scratch =
        [
            [[], [], [], [], [], [], []],
            [[], [], [], [], [], [], []],
            [[], [], [], [], [], [], []]
        ];

    /** @lends */
    return function (w, x, depth, len) {

        // Access scratch space of this depth. Due to the depth-first
        // structure of this algorithm no overwriting can take place.
        var s = scratch[depth];
        var h = s[0];
        var l = s[1];
        var z2 = s[2];
        var z1 = s[3];
        var z0 = s[4];
        var xdif = s[5];

        // Make sure that the arrays have proper sizes.
        if (typeof len === "undefined") {
            len = x.length;
        }
        len += len % 2;
        var half_len = len >>> 1;

        if (h.length !== half_len) {

            resize(h, half_len);
            resize(l, half_len);

            resize(z2, len);
            resize(z1, len);
            resize(z0, len);

            resize(xdif, half_len);
        }

        // Split the input x into higher and lower parts.
        karatsuba_split(l, h, x);

        if (depth < 1) {
            square_naive(z2, h);
            square_naive(z0, l);
        } else {
            square_karatsuba(z2, h, depth - 1);
            square_karatsuba(z0, l, depth - 1);
        }

        // We guess which is bigger and correct the result if needed.
        if (sub(xdif, h, l) < 0) {
            sub(xdif, l, h);
        }

        if (depth < 1) {
            square_naive(z1, xdif);
        } else {
            square_karatsuba(z1, xdif, depth - 1);
        }

        // Specialized loop to compute:
        // b^2 * z2 + b * (z0 - z1 + z2) + z0
        // where b = 2^(half_len * M4_WORDSIZE). We do it as follows:
        // w = b^2 * z2 + b * (z0 + z2) + z0
        // w = w - b * z1

        var tmp;
        var c = 0;
        var i = 0;
        while (i < half_len) {
            w[i] = z0[i];
            i++;
        }
        while (i < len) {

            tmp = z0[i] + z0[i - half_len] + z2[i - half_len] + c;

            // This implies, so we can safely add within 32 bits using
            // unsigned left shift.
            // tmp < 2^{M4_WORDSIZE + 2}

            w[i] = tmp & M4_MASK_ALL;
            c = tmp >>> M4_WORDSIZE;
            i++;
        }
        while (i < len + half_len) {
            tmp = z0[i - half_len] + z2[i - half_len] + z2[i - len] + c;

            // This implies, so we can safely add within 32 bits using
            // unsigned left shift.
            // tmp < 2^(M4_WORDSIZE + 2)

            w[i] = tmp & M4_MASK_ALL;
            c = tmp >>> M4_WORDSIZE;
            i++;
        }
        while (i < 2 * len) {
            tmp = z2[i - len] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >>> M4_WORDSIZE;
            i++;
        }

        // We can ignore the positive carry here, since we know that
        // the final result fits within 2 * len words, but we need to
        // subtract z1 at the right position.

        i = half_len;
        c = 0;
        while (i < len + half_len) {
            tmp = w[i] - z1[i - half_len] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >> M4_WORDSIZE;
            i++;
        }
        while (i < 2 * len) {
            tmp = w[i] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >> M4_WORDSIZE;
            i++;
        }
        // Again, we ignore the carry.

        // This guarantees that the result is correct even if w has
        // more than L + L' words.
        while (i < w.length) {
            w[i] = 0;
            i++;
        }
    };
})();
/* jshint +W074 */ /* Stop ignoring maxcomplexity. */

/**
 * @description Sets w = x * x.
 *
 * <p>
 *
 * ASSUMES: x is non-negative with L and L' limbs respectively, and
 * that w has at least L + L' limbs.
 *
 * <p>
 *
 * References: HAC 14.16.
 *
 * @param w Array holding the result.
 * @param x Factor.
 * @param len Actual lengths of inputs. Useful when stored in longer arrays.
 * @function square
 * @memberof verificatum.arithm.li
 */
var square = function (w, x, len) {

    // Only use Karatsuba if the inputs are not too big.
    var xlen = msword(x) + 1;
    if (xlen > KARATSUBA_SQR_THRESHOLD) {
        square_karatsuba(w, x, 0, len);
    } else {
        square_naive(w, x);
    }
};

/**
 * @description Sets w = x * y.
 *
 * <p>
 *
 * ASSUMES: x and y are both non-negative with L and L' limbs
 * respectively, and that w has at least L + L' limbs.
 *
 * <p>
 *
 * References: HAC 14.12.
 *
 * @param w Array holding the result.
 * @param x Left factor.
 * @param y Right factor.
 * @function mul_naive
 * @memberof verificatum.arithm.li
 */
var mul_naive = function (w, x, y) {
    var n = msword(x) + 1;
    var t = msword(y) + 1;

    setzero(w);

    for (var i = 0; i < t; i++) {
        w[i + n] = muladd_loop(w, x, 0, n, y[i], i, 0);
    }
};

/**
 * @description Sets w = x * y. The depth parameter determines the
 * recursive depth of function calls and must be less than 3.
 *
 * <p>
 *
 * ASSUMES: x and y are both non-negative, with L and L' limbs
 * respectively, and that w has at least L + L' limbs.
 *
 * <p>
 *
 * References: HAC <sectionsign>14.2,
 * https://en.wikipedia.org/wiki/Karatsuba_algorithm
 *
 * @param w Array holding the result.
 * @param x Left factor.
 * @param y Right factor.
 * @param depth Recursion depth of the Karatsuba algorithm.
 * @param len Actual lengths of inputs. Useful when stored in longer arrays.
 * @function mul_karatsuba
 * @memberof verificatum.arithm.li
 */
var mul_karatsuba = (function () {

    // Scratch space indexed by depth. These arrays are resized as
    // needed in each call. In typical cryptographic applications big
    // integers have the same size, so no resize takes place.
    var scratch =
        [
            [[], [], [], [], [], [], [], [], [], [], []],
            [[], [], [], [], [], [], [], [], [], [], []],
            [[], [], [], [], [], [], [], [], [], [], []]
        ];

    /** @lends */
    return function (w, x, y, depth, len) {

        // Access scratch space of this depth. Due to the depth-first
        // structure of this algorithm no overwriting can take place.
        var s = scratch[depth];
        var hx = s[0];
        var lx = s[1];
        var hy = s[2];
        var ly = s[3];
        var z2 = s[4];
        var z1 = s[5];
        var z0 = s[6];
        var xsum = s[7];
        var ysum = s[8];
        var tmp1 = s[9];
        var tmp2 = s[10];

        setzero(w);

        // Make sure that the lengths of the arrays are equal and
        // even.
        if (typeof len === "undefined") {
            len = Math.max(x.length, y.length);
        }
        len += len % 2;
        var half_len = len >>> 1;

        if (hx.length !== half_len) {

            resize(hx, half_len);
            resize(lx, half_len);
            resize(hy, half_len);
            resize(ly, half_len);

            resize(z2, len);
            resize(z1, len + 2);
            resize(z0, len);

            resize(xsum, half_len + 1);
            resize(ysum, half_len + 1);

            resize(tmp1, len + 2);
            resize(tmp2, len + 2);
        }

        // Split the input x and y into higher and lower parts.
        karatsuba_split(lx, hx, x);
        karatsuba_split(ly, hy, y);

        if (depth < 1) {
            mul_naive(z2, hx, hy);
            mul_naive(z0, lx, ly);
        } else {
            mul_karatsuba(z2, hx, hy, depth - 1);
            mul_karatsuba(z0, lx, ly, depth - 1);
        }

        add(xsum, hx, lx);
        add(ysum, hy, ly);

        if (depth < 1) {
            mul_naive(tmp1, xsum, ysum);
        } else {
            mul_karatsuba(tmp1, xsum, ysum, depth - 1);
        }

        sub(tmp2, tmp1, z2);
        sub(z1, tmp2, z0);

        // Specialized loop to combine the results.
        var tmp;
        var c = 0;
        var i = 0;
        while (i < half_len) {
            w[i] = z0[i];
            i++;
        }
        while (i < len) {
            tmp = z0[i] + z1[i - half_len] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >>> M4_WORDSIZE;
            i++;
        }
        while (i < len + half_len + 2) {
            tmp = z1[i - half_len] + z2[i - len] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >>> M4_WORDSIZE;
            i++;
        }
        while (i < 2 * len) {
            tmp = z2[i - len] + c;
            w[i] = tmp & M4_MASK_ALL;
            c = tmp >>> M4_WORDSIZE;
            i++;
        }

        // This guarantees that the result is correct even if w has more
        // than L + L' words.
        while (i < w.length) {
            w[i] = 0;
            i++;
        }
    };
})();

/**
 * @description Sets w = x * y.
 *
 * <p>
 *
 * ASSUMES: x and y are both non-negative with L and L' limbs
 * respectively, and that w has at least L + L' limbs.
 *
 * @param w Array holding the result.
 * @param x Left factor.
 * @param y Right factor.
 * @param len Actual lengths of inputs. Useful when stored in longer arrays.
 * @function mul
 * @memberof verificatum.arithm.li
 */
var mul = function (w, x, y, len) {

    if (x === y) {
        square(w, x);
    } else {

        // Only use Karatsuba if the inputs are relatively balanced
        // and not too small.
        var xlen = msword(x) + 1;
        var ylen = msword(y) + 1;
        if (xlen > KARATSUBA_MUL_THRESHOLD &&
            Math.min(xlen / ylen, ylen / xlen) > KARATSUBA_RELATIVE) {
            mul_karatsuba(w, x, y, 0, len);
        } else {
            mul_naive(w, x, y);
        }
    }
};

/* jshint -W126 */ /* Ignore singleGroups */
/* eslint-disable no-extra-parens */
/**
 * @description Computes the 2-by-1 reciprocal of a word d.
 *
 * <p>
 *
 * ASSUMES: most significant bit of d is set, i.e., we have
 * 2^M4_WORDSIZE/2 <= d < 2^M4_WORDSIZE.
 *
 * <p>
 *
 * References: Functionally equivalent to RECIPROCAL_WORD in MG.
 *
 * @param d Normalized divisor.
 * @return 2-by-1 reciprocal of d.
 * @function reciprocal_word
 * @memberof verificatum.arithm.li
 */
var reciprocal_word = (function () {

    // Temporary variables.
    var q = [0, 0];
    var a = [0, 0];
    var p = [0, 0, 0];
    var r = [0, 0, 0];
    var one = [1];
    var zero = [0];
    var dd = [0];

    var two_masks = [M4_MASK_ALL, M4_MASK_ALL];

    /** @lends */
    return function (d) {

        var s;
        var N;
        var A;
        dd[0] = d;

        set(r, two_masks);

        setzero(q);
        do {

            // If r does not fit in a float, we shift it and the
            // divisor before computing the estimated quotient.
            s = Math.max(0, msbit(r) - M4_MANTISSA);
            N = r[1] * Math.pow(2, M4_WORDSIZE - s) + (r[0] >> s);
            A = Math.floor(N / d);

            // Approximation of quotient as two-word integer.
            a[0] = A & M4_MASK_ALL;
            a[1] = (A >>> M4_WORDSIZE);
            shiftleft(a, s);

            // p = a * d
            mul(p, a, dd);

            // Correct the estimate if needed. This should not happen,
            // due to taking the floor, but floating point arithmetic
            // is not robust over platforms, so let us be defensive.
            while (cmp(p, r) > 0) {
                sub(a, a, one);
                sub(p, p, dd);
            }

            // r = r - q * d
            sub(r, r, p);
            add(q, q, a);

        } while (cmp(a, zero) > 0);

        // For code like this it is not robust to condition on r < d,
        // since it is conceivable that A and hence a is zero despite
        // that r > d. This turns out to not be the case here, but we
        // write defensive code.
        while (cmp(r, dd) >= 0) {
            add(q, q, one);
            sub(r, r, dd);
        }

        // q = q - 2^M4_WORDSIZE
        return q[0] & M4_MASK_ALL;
    };
})();

/**
 * @description Computes the 3-by-2 reciprocal of d, where d has two
 * limbs/words.
 *
 * <p>
 *
 * ASSUMES: most significant bit of d is set, i.e., we have
 * 2^(2 * M4_WORDSIZE)/2 <= d < 2^(2*M4_WORDSIZE).
 *
 * <p>
 *
 * References: Algorithm RECIPROCAL_WORD_3BY2 in MG.
 *
 * @param d Normalized divisor.
 * @return 3-by-2 reciprocal of d.
 * @function reciprocal_word_3by2
 * @memberof verificatum.arithm.li
 */
var reciprocal_word_3by2 = (function () {

    var t = [0, 0];

    /** @lends */
    return function (d) {

        var v = reciprocal_word(d[1]);

        // p = d1 * v mod 2^M4_WORDSIZE
        word_mul(t, d[1], v);

        var p = t[0];

        // p = p + d0 mod 2^M4_WORDSIZE
        p = (p + d[0]) & M4_MASK_ALL;

        // p < d0
        if (p < d[0]) {
            v--;

            // p >= d1
            if (p >= d[1]) {
                v--;
                p = p - d[1];
            }
            p = (p + M4_TWO_POW_WORDSIZE - d[1]) & M4_MASK_ALL;
        }

        // t = p * d0
        word_mul(t, v, d[0]);

        // p = p + t1 mod 2^M4_WORDSIZE
        p = (p + t[1]) & M4_MASK_ALL;

        if (p < t[1]) {
            v--;

            // (p,t0) >= (d1,d0)
            if (p > d[1] || (p === d[1] && t[0] >= d[0])) {
                v--;
            }
        }
        return v;
    };
})();

/**
 * @description Computes q and r such that u = q * d + r, where d has
 * two limbs/words, d has three limbs/words, and 0 <= r < d.
 *
 * <p>
 *
 * ASSUMES: most significant bit of d is set, i.e., we have
 * 2^(2 * M4_WORDSIZE)/2 <= d < 2^(2*M4_WORDSIZE).
 *
 * <p>
 *
 * References: Algorithm DIV3BY2 in MG.
 *
 * @param r Two-word integer that ends up holding the remainder.
 * @param u Three-word dividend.
 * @param d Normalized divisor.
 * @param neg_d Negative of d in two's complement.
 * @param v 3by2 reciprocal of d.
 * @return Integer quotient q = u / d.
 * @function div3by2
 * @memberof verificatum.arithm.li
 */
var div3by2 = (function () {

    // Temporary variables.
    var q = [0, 0];
    var neg_t = [0, 0];

    /** @lends */
    return function (r, u, d, neg_d, v) {

        var tmp = 0;

        // (q1,q0) = v * u2
        word_mul(q, v, u[2]);

        // q = q + (u2,u1)
        M4_LONG_ADD2(q[1], q[0], u[2], u[1], tmp);

        // r1 = u1 - q1 * d1 mod 2^M4_WORDSIZE
        word_mul(r, q[1], d[1]);
        r[1] = (u[1] + M4_TWO_POW_WORDSIZE - r[0]) & M4_MASK_ALL;

        // neg_t = d0 * q1
        word_mul(neg_t, d[0], q[1]);
        neg(neg_t, neg_t);

        // r = (r1,u0) - t - d mod 2^(2 * M4_WORDSIZE)
        r[0] = u[0];
        M4_LONG_ADD2(r[1], r[0], neg_t[1], neg_t[0], tmp);
        M4_LONG_ADD2(r[1], r[0], neg_d[1], neg_d[0], tmp);

        // q1 = q1 + 1 mod 2^M4_WORDSIZE
        q[1] = (q[1] + 1) & M4_MASK_ALL;

        // r1 >= q0
        if (r[1] >= q[0]) {

            // q1 = q1 - 1 mod 2^M4_WORDSIZE
            q[1] = (q[1] + M4_MASK_ALL) & M4_MASK_ALL;

            // r = r + d mod 2^(2 * M4_WORDSIZE)
            M4_LONG_ADD2(r[1], r[0], d[1], d[0], tmp);
        }

        // r >= d
        if (r[1] > d[1] || (r[1] === d[1] && r[0] >= d[0])) {

            // q1 = q1 + 1
            q[1] = q[1] + 1;

            // r = r - d
            M4_LONG_ADD(r, neg_d, tmp);
        }

        return q[1];
    };
})();
/* jshint +W126 */ /* Stop ignoring singleGroups */
/* eslint-enable no-extra-parens */

/**
 * @description Sets q and r such that x = qy + r, except that r is
 * computed in place of x, so at the end of the execution x is
 * identified with r. WARNING! y is cached in its normalized form
 * along with its negation and reciprocal. This is pointer based,
 * i.e., it is assumed that the contents of y do not change. High
 * level routines must accomodate.
 *
 * <p>
 *
 * ASSUMES: x and y are positive, x has L words and at least L + 2
 * limbs (i.e., two leading unused zero words), y has L' limbs, and q
 * has at least L'' = max{L - L', 0} + 1 limbs and will finally hold a
 * result with at most L'' words and a leading zero limb.
 *
 * <p>
 *
 * References: HAC 14.20.
 *
 * @param q Holder of quotient.
 * @param x Divident and holder of remainder at end of computation.
 * @param y Divisor.
 * @function div_qr
 * @memberof verificatum.arithm.li
 */
var div_qr = (function () {

    // y from the previous call.
    var old_y = null;

    // Normalized y.
    var ny = [];

    // Negative of normalized y.
    var neg_ny = [];

    // Bits shifted left to normalize.
    var normdist;

    // Index of most significant word of ny.
    var t;

    // Reciprocal for 3by2 division.
    var v;

    // Most significant 3 words of x shifted to accomodate for the
    // normalization of y.
    var u = [0, 0, 0];

    // Top two words of ny.
    var d = [0, 0];

    // Negative of d in two's complement.
    var neg_d = [0, 0];

    // Remainder in 3by2 division.
    var r = [0, 0];

    // Normalizes y and computes reciprocals.
    var initialize_y = function (y) {

        if (y === old_y) {
            return;
        }
        old_y = y;

        // Make sure we have room for a normalized copy ny of y and a
        // negative of ny.
        if (neg_ny.length !== y.length + 1) {
            resize(neg_ny, y.length + 1);
            ny.length = y.length;
        }

        // Make copy of y.
        set(ny, y);
        
        // Determine a normalization distance.
        normdist =
        (M4_WORDSIZE - (msbit(ny) + 1) % M4_WORDSIZE) % M4_WORDSIZE;

        shiftleft(ny, normdist);

        // Compute the negative of ny in two's complement, but drop
        // the carry that equals -1 in the end. Note that neg_ny has
        // one more limb than ny, which is safe since the carry is
        // not used.
        neg(neg_ny, ny);

        // Index of most significant word of ny.
        t = msword(ny);

        // Extract top two words of y and their negative.
        d[1] = ny[t];
        d[0] = t > 0 ? ny[t - 1] : 0;
        neg(neg_d, d);

        // Sets the reciprocal of d.
        v = reciprocal_word_3by2(d);
    };

    // Returns true or false depending on if x >= s(y) or not, where
    // s(y) = y * 2^((n - t) * M4_WORDSIZE), i.e., s(y) is y shifted by
    // n - t words to the left, and n and t are the indices of the
    // most significant words of x and y respectively.
    var shiftleft_ge = function (x, n, y, t) {

        var i = n;
        var j = t;

        while (j >= 0) {
            if (x[i] > y[j]) {
                return true;
            } else if (x[i] < y[j]) {
                return false;
            }
            i--;
            j--;
        }

        // When the top t + 1 words of x and s(y) are identical, we
        // would compare the remaining (n + 1) - (t + 1) = n - 1
        // words, but the bottom offset words of s(y) are zero, so in
        // this case x >= s(y).
        return true;
    };

    /** @lends */
    return function (w, x, y) {
        
        // Index of most significant word of x.
        var n;

        var i;
        var j;
        var k;
        var l;
        var tmp;
        var c;

        // Set quotient to zero.
        setzero(w);

        // If x < y, then simply return.
        if (cmp(x, y) < 0) {
            return;
        }

        // Initialize division with y. Normalization, reciprocals etc.
        initialize_y(y);

        // Left shift x to accomodate for normalization of y.
        shiftleft(x, normdist);

        // Index of most significant word of x.
        n = msword(x);

        // Since x > ny, we know that n >= t > 0. Pseudo-code:
        //
        // while (x >= ny * 2^((n - t) * wordsize)) {
        //     w[n - t] = w[n - t] + 1
        //     x = x - ny * 2^((n - t) * wordsize)
        // }
        //
        // Note that due to the normalization, for random inputs the
        // number of executions of this loop is probably small.
        while (shiftleft_ge(x, n, ny, t)) {
            i = 0;
            j = n - t;
            c = 0;
            while (i < t + 1) {
                tmp = x[j] - ny[i] + c;

                x[j] = tmp & M4_MASK_ALL;
                c = tmp >> M4_WORDSIZE;
                i++;
                j++;
            }
            w[n - t]++;
        }

        for (i = n; i >= t + 1; i--) {

            // This remains constant within each execution of the loop
            // and only used for notational convenience.
            k = i - t - 1;

            // Estimate w[k] using reciprocal for top two words of ny.
            u[2] = x[i];
            u[1] = i > 0 ? x[i - 1] : 0;
            u[0] = i > 1 ? x[i - 2] : 0;

            if (u[2] === d[1] && u[1] >= d[0]) {
                w[k] = M4_MASK_ALL;
            } else {
                w[k] = div3by2(r, u, d, neg_d, v);
            }

            // Subtract scaled and shifted ny from x.
            muladd_loop(x, neg_ny, 0, t + 2, w[k], k, 0);

            // We now expect x[i] to be zero, i.e., that we have
            // cancelled one word of x. In the unlikely event that the
            // estimate of w[k] is too big, we need to correct the
            // result by adding a scaled ny once to x.
            //
            // By construction 0 <= w[k] < 2^M4_WORDSIZE. Thus, if w[k]
            // is too big, then x[i] is -1 in two's complement, i.e.,
            // equal to M4_MASK_ALL.
            if (x[k + t + 1] === M4_MASK_ALL) {
                l = 0;
                j = k;
                c = 0;
                while (l < t + 1) {
                    tmp = x[j] + ny[l] + c;

                    x[j] = tmp & M4_MASK_ALL;
                    c = tmp >> M4_WORDSIZE;
                    l++;
                    j++;
                }
                tmp = x[j] + c;
                x[j] = tmp & M4_MASK_ALL;
                j++;
                if (j < x.length) {
                    x[j] = 0;
                }
                w[k]--;
            }
        }

        // Denormalize x.
        shiftright(x, normdist);
    };
})();

/**
 * @description Sets w = b^e mod m.
 *
 * <p>
 *
 * ASSUMES: b >= 0, e >= 0, and m > 1, and w, b and m have L limbs.
 *
 * <p>
 *
 * References: HAC 14.82.
 *
 * @param w Array holding the result.
 * @param b Basis integer.
 * @param e Exponent.
 * @param m Modulus.
 * @function modpow_naive
 * @memberof verificatum.arithm.li
 */
var modpow_naive = (function () {

    // We use p to store squares, products, and their remainders, q to
    // store quotients during modular reduction, and A to store
    // intermediate results.
    var p = [];
    var q = [];
    var A = [];

    /** @lends */
    return function (w, b, e, m) {

        // Initialize or resize temporary space as needed.
        if (A.length !== m.length) {
            resize(p, 2 * m.length + 2);
            resize(q, m.length);
            resize(A, m.length);
        }

        // Index of most significant bit.
        var n = msbit(e);

        // We avoid one squaring.
        if (getbit(e, n) === 1) {

            set(p, b);
            div_qr(q, p, m);
            set(A, p);

        }

        // Iterate through the remaining bits of e starting from the
        // most significant bit.
        for (var i = n - 1; i >= 0; i--) {

            // A = A^2 mod m.
            square(p, A);

            div_qr(q, p, m);
            set(A, p);

            if (getbit(e, i) === 1) {

                // A = A * b mod m.
                mul(p, A, b);
                div_qr(q, p, m);
                set(A, p);
            }
        }
        set(w, A);
    };
})();

/**
 * @description Extracts the ith block of wordsize bits w from x
 * (padding with zeros from the left) and sets uh such that:
 * w = uh[0] * 2^uh[1], with uh[0] odd and with uh[0] = uh[1] = 0
 * when w = 0.
 * @param uh Holds the representation of word.
 * @param x Contains bits.
 * @param i Index of block of bits.
 * @param wordsize Number of bits in each block.
 * @function getuh
 * @memberof verificatum.arithm.li
 */
var getuh = function (uh, x, i, wordsize) {
    var bitIndex = i * wordsize;

    // Get the ith block of wordsize bits.
    uh[0] = 0;
    for (var j = 0; j < wordsize; j++) {
        uh[0] = uh[0] | getbit(x, bitIndex) << j;
        bitIndex++;
    }

    // Extract all factors of two.
    uh[1] = 0;
    if (uh[0] !== 0) {
        while ((uh[0] & M4_MASK_LSB) === 0) {
            uh[0] = uh[0] >>> 1;
            uh[1]++;
        }
    }
};

/* jshint -W074 */ /* Ignore maxcomplexity. */
/**
 * @description Sets w = b^e mod m.
 *
 * <p>
 *
 * ASSUMES: b >= 0, e >= 0, and m > 1, and w, b and m have L limbs.
 *
 * <p>
 *
 * References: HAC 14.83.
 *
 * @param w Array holding the result.
 * @param b Basis integer.
 * @param e Exponent.
 * @param m Modulus.
 * @function modpow
 * @memberof verificatum.arithm.li
 */
var modpow = (function () {

    // We use p to store squares, products, and their remainders, q to
    // store quotients during modular reduction, and A to store
    // intermediate results.
    var p = [];
    var q = [];
    var A = [];
    var B = [];

    /** @lends */
    return function (w, b, e, m) {

        var i;
        var j;
        var msb = msbit(m) + 1;

        // Thresholds for pre-computation. These are somewhat
        // arbitrary, since they are likely to differ with the
        // wordsize and JavaScript engine.
        var k = 2;
        if (msb > 512) {
            k++;
        }
        if (msb > 640) {
            k++;
        }
        if (msb > 768) {
            k++;
        }
        if (msb > 896) {
            k++;
        }
        if (msb > 1280) {
            k++;
        }
        if (msb > 2688) {
            k++;
        }
        if (msb > 3840) {
            k++;
        }

        // Initialize or resize temporary space as needed.
        if (A.length !== m.length) {
            resize(p, 2 * m.length + 2);
            resize(q, m.length);
            resize(A, m.length);

            var len = B.length;
            for (i = 0; i < len; i++) {
                if (B[i].length !== m.length) {
                    resize(B[i], m.length);
                }
            }
            if (len < 1 << k) {
                B.length = 1 << k;
                for (i = len; i < B.length; i++) {
                    B[i] = newarray(m.length);
                }
            }
        }

        // Precompute table
        // B[0] = 1.
        B[0][0] = 1;

        // B[1] = b
        set(B[1], b);

        // B[2] = b^2 mod m
        square(p, b);
        div_qr(q, p, m);
        set(B[2], p);

        // B[i] = B[i - 1] * b^2 mod m
        for (i = 1; i < 1 << k - 1; i++) {
            mul(p, B[2 * i - 1], B[2]);
            div_qr(q, p, m);
            set(B[2 * i + 1], p);
        }

        // Set A = 1.
        setzero(A);
        A[0] = 1;

        // Iterate through the bits of e starting from the most
        // significant block of bits.
        var n = Math.floor((msbit(e) + k - 1) / k);

        var uh = [0, 0];
        for (i = n; i >= 0; i--) {

            // Extract the ith block of bits w and represent it as w =
            // uh[0] * 2^uh[1], with uh[0] odd and with uh[0] = uh[1]
            // = 0 when w = 0.
            getuh(uh, e, i, k);

            // A = A^E mod m, where E = 2^(k - uh[1]).
            for (j = 0; j < k - uh[1]; j++) {
                square(p, A);
                div_qr(q, p, m);
                set(A, p);
            }

            // A = A * B[uh[0]] mod m.
            if (uh[0] !== 0) {
                mul(p, A, B[uh[0]]);
                div_qr(q, p, m);
                set(A, p);
            }

            // A = A^E mod m, where E = 2^uh[1].
            for (j = 0; j < uh[1]; j++) {
                square(p, A);
                div_qr(q, p, m);
                set(A, p);
            }
        }
        set(w, A);
    };
})();
/* jshint +W074 */ /* Stop ignoring maxcomplexity. */

/**
 * @description Returns a table of all possible modular products of a
 * list of bases. More precisely, given a list b of k bases and a
 * modulus m, it returns [k, t], where t is the table computed as t[x]
 * = b[0]^x[0] * ... * b[k-1]^x[k-1] mod m, where x[i] is the ith bit
 * of the integer x.
 *
 * <p>
 *
 * ASSUMES: m has L limbs and b[i] has L limbs for i = 0,...,k-1 and
 * all inputs are positive.
 *
 * @param b List of bases.
 * @param m Modulus.
 * @return t Table for products.
 * @class
 * @memberof verificatum.arithm
 */
var modpowprodtab = (function () {

    // We use p to store products and q to store quotients during
    // modular reduction.
    var p = [];
    var q = [];

    /** @lends */
    return function (b, m) {

        var i;
        var j;

        // Initialize or resize temporary space as needed.
        if (q.length !== m.length) {
            resize(p, 2 * m.length + 2);
            resize(q, m.length);
        }

        // Make room for table and initialize all elements to one.
        var t = [];
        for (i = 0; i < 1 << b.length; i++) {
            t[i] = newarray(m.length);
            t[i][0] = 1;
        }

        // Init parts of the table with the bases provided.
        for (i = 1, j = 0; i < t.length; i = i * 2, j++) {
            set(t[i], b[j]);
        }

        // Perform precalculation using masking for efficiency.
        for (var mask = 1; mask < t.length; mask++) {

            var onemask = mask & -mask;
            mul(p, t[mask ^ onemask], t[onemask]);
            div_qr(q, p, m);
            set(t[mask], p);
        }

        return t;
    };
})();

/**
 * @description Computes a simultaneous exponentiation using a table
 * of pre-computed values t for k bases b[0],...,b[k-1] and modulus m,
 * i.e., it sets w = b[0]^e[0] * ... * b[k-1]^e[k-1].
 *
 * <p>
 *
 * ASSUMES: m > 1 has L limbs and e[i] has L limbs for i = 0,...,k - 1
 * and all inputs are positive, and that the table was computed with
 * the same number k of bases and the same modulusm.
 *
 * @param w Holds the result.
 * @param t Table of products.
 * @param e List of k exponents.
 * @param m Modulus
 * @class
 * @memberof verificatum.arithm
 */
var modpowprod = (function () {

    // We use p to store squares, products, and their remainders, q to
    // store quotients during modular reduction, and A to store
    // intermediate results.
    var p = [];
    var q = [];
    var A = [];

    /** @lends */
    return function (w, t, e, m) {

        var i;

        // Initialize or resize temporary space as needed.
        if (A.length !== m.length) {
            resize(p, 2 * m.length + 2);
            resize(q, m.length);
            resize(A, m.length);
        }

        // Determine maximal most significant bit position.
        var l = msbit(e[0]);
        for (i = 1; i < e.length; i++) {
            l = Math.max(msbit(e[i]), l);
        }

        // Set A = 1.
        setone(A);

        for (i = l; i >= 0; i--) {

            var x = 0;

            // A = A^2 mod m.
            square(p, A);
            div_qr(q, p, m);
            set(A, p);

            // Loop over exponents to form a word x from all the bits
            // at a given position.
            for (var j = 0; j < e.length; j++) {

                if (getbit(e[j], i) === 1) {

                    x |= 1 << j;
                }
            }

            // Look up product in pre-computed table if needed.
            if (x !== 0) {

                // A = A * t[x] mod m.
                mul(p, A, t[x]);
                div_qr(q, p, m);
                set(A, p);
            }
        }
        set(w, A);
    };
})();

/**
 * @description Returns the bits between the start index and end index
 * as an integer.
 *
 * <p>
 *
 * ASSUMES: s <= most significant bit of x and s < e
 *
 * @param x Integer to slice.
 * @param s Inclusive start index.
 * @param e Exclusive end index.
 * @return Bits between the start index and end index as an integer.
 * @method
 */
var slice = function (x, s, e) {
    var m = msbit(x);

    // Avoid indexing out of bounds.
    e = Math.min(e, m + 1);

    // Copy and get rid of the lower bits.
    var w = copyarray(x);
    shiftright(w, s);

    // Get rid of higher words.
    var bitlen = e - s;
    w.length = Math.floor((bitlen + M4_WORDSIZE - 1) / M4_WORDSIZE);

    // Get rid of top-most bits.
    var topbits = bitlen % M4_WORDSIZE;
    if (topbits > 0) {
        w[w.length - 1] &= M4_MASK_ALL >>> M4_WORDSIZE - topbits;
    }
    return w;
};

/**
 * @description Returns a hexadecimal representation of this input
 * array by content, i.e., unused bits of each limb are dropped before
 * conversion
 * @param x Array of words.
 * @return Hexadecimal string representation of the array.
 * @function hex
 * @memberof verificatum.arithm.li
 */
var hex = function (x) {
    var dense = util.change_wordsize(x, M4_WORDSIZE, 8);
    normalize(dense);
    return util.byteArrayToHex(dense.reverse());
};

        
var hex_to_li = function (s) {
    var b = util.hexToByteArray(s);
    var r = b.reverse();
    return util.change_wordsize(r, 8, M4_WORDSIZE);
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
                                                                   // DEBUG
    var noWords =                                                  // DEBUG
        Math.floor((bitLength + M4_WORDSIZE - 1) / M4_WORDSIZE);   // DEBUG
    var zeroBits = noWords * M4_WORDSIZE - bitLength;              // DEBUG
                                                                   // DEBUG
    var x = [];                                                    // DEBUG
    for (var i = 0; i < noWords; i++) {                            // DEBUG
        x[i] = Math.floor(Math.random() * M4_TWO_POW_WORDSIZE);    // DEBUG
    }                                                              // DEBUG
    x[x.length - 1] &= M4_MASK_ALL >>> zeroBits;                   // DEBUG
    normalize(x);                                                  // DEBUG
                                                                   // DEBUG
    return x;                                                      // DEBUG
};                                                                 // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES     DEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG

return {
    "WORDSIZE": WORDSIZE,

    "newarray": newarray,
    "copyarray": copyarray,
    "resize": resize,
    "normalize": normalize,

    "setzero": setzero,
    "setone": setone,
    "set": set,

    "msbit": msbit,
    "lsbit": lsbit,
    "msword": msword,

    "getbit": getbit,
    "iszero": iszero,
    "cmp": cmp,
    "shiftleft": shiftleft,
    "shiftright": shiftright,

    "add": add,
    "sub": sub,
    "mul": mul,
    "mul_naive": mul_naive,
    "mul_karatsuba": mul_karatsuba,
    "square": square,
    "square_naive": square_naive,
    "square_karatsuba": square_karatsuba,

    "div_qr": div_qr,
    "modpow_naive": modpow_naive,
    "modpow": modpow,

    "modpowprodtab": modpowprodtab,
    "modpowprod": modpowprod,
    "slice": slice,

    "hex": hex,
    "hex_to_li": hex_to_li,

    "muladd_loop": muladd_loop,
    "neg": neg,
    "reciprocal_word": reciprocal_word,
    "reciprocal_word_3by2": reciprocal_word_3by2,
    "div3by2": div3by2,
    "word_mul": word_mul,

    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    // DEBUG                                                  DEBUGDEBU// DEBUG
    // DEBUG   WARNING! ONLY FOR DEBUGGING PURPOSES           DEBUGDEBU// DEBUG
    // DEBUG                                                  DEBUGDEBU// DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
    "INSECURErandom": INSECURErandom                               // DEBUG
    // DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
};

})();
