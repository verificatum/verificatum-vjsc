
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
// ################### LargeInteger #####################################
// ######################################################################

/* jshint -W074 */ /* Ignore maxcomplexity. */
/**
 * @description Class for large immutable integers that handles memory
 * allocation and provided utility functions.
 * @param first Can be: (1) sign of explicit integer, (2) bit length
 * of random integer, (3) byte array containing the bits of an
 * integer, (4) hexadecimal representation of integer, (5) byte tree
 * representation of integer, or (6) Javascript "number"
 * representation of integer.
 * @param second Can be: (1) value of explicit integer, (2) or source
 * of randomness, or in cases (3)-(6) it must be empty.
 * @class
 * @memberof verificatum.arithm
 */
function LargeInteger(first, second) {
    sli.SLI.call(this);

    var sign;
    var value;

    if (typeof second !== "undefined") {

        // Verbatim integer from inputs. Here first is the sign of the
        // integer and second is the array representing the integer.
        if (util.ofType(second, "array")) {

            sign = first;
            value = second;

            // Non-negative random integer, here first is the bit length
            // and second is a RandomSource.
        } else {

            var byteLength = LargeInteger.byteLengthRandom(first);
            var topZeros = (8 - first % 8) % 8;

            var data = second.getBytes(byteLength);

            data[0] &= 0xFF >>> topZeros;
            var reversed = data.reverse();

            value = util.change_wordsize(reversed, 8, li.WORDSIZE);

            if (li.iszero(value)) {
                sign = 0;
            } else {
                sign = 1;
            }
        }

        // Integer from byte array.
    } else if (util.ofType(first, "array")) {

        value = util.change_wordsize(first.slice().reverse(), 8, li.WORDSIZE);

        if (li.iszero(value)) {
            sign = 0;
        } else {
            sign = 1;
        }

        // Integer from signed hexadecimal representation.
    } else if (util.ofType(first, "string")) {

        // We assume that the first input is a hexadecimal value to be
        // converted if only one input is given.
        var hex = first;
        var i = 0;

        // Set the sign.
        if (hex[i] === "-") {
            sign = -1;
            i++;
        } else {
            sign = 1;
        }

        // Ignore leading zeros.
        while (i < hex.length && hex[i] === "0") {
            i++;
        }

        // Set to zero or shorten input as appropriate.
        if (i === hex.length) {
            sign = 0;
            hex = "00";
        } else {
            hex = hex.substring(i, hex.length);
        }

        // Convert to an array of bytes in reverse order and of proper
        // wordsize.
        var array = util.hexToByteArray(hex).reverse();
        value = util.change_wordsize(array, 8, li.WORDSIZE);

        // Create instance from byte tree.
    } else if (util.ofType(first, "object")) {

        if (!first.isLeaf()) {
            throw Error("Expected a leaf!");
        }
        var tmp = new LargeInteger(first.value);
        sign = tmp.sign;
        value = tmp.value;

        // Create empty instance to be modified by functions from sli.js.
    } else if (util.ofType(first, "number")) {
        sign = 0;
        value = li.newarray(first);
    } else {
        /* istanbul ignore next */
        throw Error("Invalid parameters!");
    }

    this.sign = sign;
    this.value = value;
    this.length = value.length;
}
LargeInteger.prototype = Object.create(sli.SLI.prototype);
LargeInteger.prototype.constructor = LargeInteger;

/* jshint +W074 */ /* Stop ignoring maxcomplexity. */

// ################### ZERO #############################################
// Representation of zero.
LargeInteger.ZERO = new LargeInteger(0, [0]);

// ################### ONE ##############################################
// Representation of one.
LargeInteger.ONE = new LargeInteger(1, [1]);

// ################### TWO ##############################################
// Representation of two.
LargeInteger.TWO = new LargeInteger(1, [2]);

/**
 * @description Returns the number of bytes needed to generate the
 * given number of bits.
 * @param bitLength Number of bits.
 * @return Number of bytes needed.
 * @function byteLengthRandom
 * @memberof verificatum.arithm.LargeInteger
 */
LargeInteger.byteLengthRandom = function (bitLength) {
    return Math.floor((bitLength + 7) / 8);
};

/**
 * @description Compares this integer with the input.
 * @param other Other integer.
 * @return -1, 0, or 1 depending on if this integer is smaller than,
 * equal to, or greater than the input.
 * @method
 */
LargeInteger.prototype.cmp = function (other) {
    if (this.sign < other.sign) {
        return -1;
    } else if (this.sign > other.sign) {
        return 1;
    } else if (this.sign === 0) {
        return 0;
    }
    return li.cmp(this.value, other.value) * this.sign;
};

/**
 * @description Checks if this integer is equal to the input.
 * @param other Other integer.
 * @return true if and only if this integer equals the input.
 * @method
 */
LargeInteger.prototype.equals = function (other) {
    return this.cmp(other) === 0;
};

/**
 * @description Checks if this integer is zero.
 * @return true or false depending on if this is zero or not.
 * @method
 */
LargeInteger.prototype.iszero = function () {
    return this.sign === 0;
};

/**
 * @description Bit length of this integer.
 * @return Bit length of this integer.
 * @method
 */
LargeInteger.prototype.bitLength = function () {
    return li.msbit(this.value) + 1;
};

/**
 * @description Returns 1 or 0 depending on if the given bit is set or
 * not.
 * @param index Position of bit.
 * @return 1 or 0 depending on if the given bit is set or not.
 * @method
 */
LargeInteger.prototype.getBit = function (index) {
    return li.getbit(this.value, index);
};

/**
 * @description Returns the absolute value of this integer.
 * @return Absolute value of this integer.
 * @method
 */
LargeInteger.prototype.abs = function () {
    return new LargeInteger(1, li.copyarray(this.value));
};

/**
 * @description Shifts this integer to the left.
 * @param offset Bit positions to shift.
 * @return This integer shifted the given number of bits to the left.
 * @method
 */
LargeInteger.prototype.shiftLeft = function (offset) {
    var len =
        this.length + Math.floor((offset + li.WORDSIZE - 1) / li.WORDSIZE);
    var value = li.copyarray(this.value);
    li.resize(value, len);
    li.shiftleft(value, offset);
    return new LargeInteger(this.sign, value);
};

/**
 * @description Shifts this integer to the right.
 * @param offset Bit positions to shift.
 * @return This integer shifted the given number of bits to the right.
 * @method
 */
LargeInteger.prototype.shiftRight = function (offset) {
    var value = li.copyarray(this.value);
    li.shiftright(value, offset);
    li.normalize(value);
    var sign = this.sign;
    if (li.iszero(value)) {
        sign = 0;
    }
    return new LargeInteger(sign, value);
};

/**
 * @description Returns negative of this integer.
 * @return -this.
 * @method
 */
LargeInteger.prototype.neg = function () {
    return new LargeInteger(-this.sign, li.copyarray(this.value));
};

/**
 * @description Computes sum of this integer and the input.
 * @param term Other integer.
 * @return this + term.
 * @method
 */
LargeInteger.prototype.add = function (term) {
    var len = Math.max(this.length, term.length) + 1;
    var res = new LargeInteger(len);
    sli.add(res, this, term);
    sli.normalize(res);
    return res;
};

/**
 * @description Computes difference of this integer and the input.
 * @param term Other integer.
 * @return this - term.
 * @method
 */
LargeInteger.prototype.sub = function (term) {
    var len = Math.max(this.length, term.length) + 1;
    var res = new LargeInteger(len);
    sli.sub(res, this, term);
    sli.normalize(res);
    return res;
};

/**
 * @description Computes product of this integer and the input.
 * @param factor Other integer.
 * @return this * term.
 * @method
 */
LargeInteger.prototype.mul = function (factor) {
    var len = this.length + factor.length;
    var res = new LargeInteger(len);
    sli.mul(res, this, factor);
    sli.normalize(res);
    return res;
};

/**
 * @description Computes square of this integer.
 * @return this * this.
 * @method
 */
LargeInteger.prototype.square = function () {
    var len = 2 * this.length;
    var res = new LargeInteger(len);
    sli.square(res, this);
    sli.normalize(res);
    return res;
};

/**
 * @description Returns [q, r] such that q = this / divisor + r with
 * this / divisor and r rounded with sign, in particular, if divisor
 * is positive, then 0 <= r < divisor.
 * @param divisor Divisor.
 * @return Quotient and divisor.
 * @method
 */
LargeInteger.prototype.divQR = function (divisor) {

    if (divisor.sign === 0) {
        /* istanbul ignore next */
        throw Error("Attempt to divide by zero!");
    }

    var dlen = divisor.length;

    // Copy this with extra space, since sli.div_qr is destructive.
    var remainder = new LargeInteger(Math.max(this.length, dlen) + 2);
    sli.set(remainder, this);

    // Make room for quotient.
    var qlen = Math.max(remainder.length - dlen, dlen, 0) + 1;
    var quotient = new LargeInteger(qlen);

    // Compute result.
    sli.div_qr(quotient, remainder, divisor);

    sli.normalize(quotient);
    sli.normalize(remainder);

    return [quotient, remainder];
};

/**
 * @description Computes integer quotient of this integer and the
 * input.
 * @param divisor Integer divisor.
 * @return this / divisor for positive integers with rounding
 * according to signs.
 * @method
 */
LargeInteger.prototype.div = function (divisor) {
    return this.divQR(divisor)[0];
};

/**
 * @description Computes integer remainder of this integer divided by
 * the input as a value in [0, modulus - 1].
 * @param modulus Divisor.
 * @return Integer remainder.
 * @method
 */
LargeInteger.prototype.mod = function (modulus) {
    return this.divQR(modulus)[1];
};

/**
 * @description Computes modular sum when this integer and the first
 * input are non-negative and the last input is positive.
 * @param term Other integer.
 * @param modulus Modulus.
 * @return (this + term) mod modulus.
 * @method
 */
LargeInteger.prototype.modAdd = function (term, modulus) {
    return this.add(term).mod(modulus);
};

/**
 * @description Computes modular difference when this integer and the
 * first input are non-negative and the last input is positive.
 * @param term Other integer.
 * @param modulus Modulus.
 * @return (this - term) mod modulus.
 * @method
 */
LargeInteger.prototype.modSub = function (term, modulus) {
    return this.sub(term).mod(modulus);
};

/**
 * @description Computes modular product when this integer and the first
 * input are non-negative and the last input is positive.
 * @param term Other integer.
 * @param modulus Modulus.
 * @return (this * term) mod modulus.
 * @method
 */
LargeInteger.prototype.modMul = function (factor, modulus) {
    return this.mul(factor).mod(modulus);
};

/**
 * @description Computes modular power of this integer raised to the
 * exponent modulo the given modulus.
 * @param exponent Exponent.
 * @param modulus Integer divisor.
 * @param naive Optional debugging parameter that enables slower naive
 * implementation.
 * @return this ^ exponent mod modulus for positive integers.
 * @method
 */
LargeInteger.prototype.modPow = function (exponent, modulus, naive) {

    if (this.sign < 0) {
        /* istanbul ignore next */
        throw Error("Negative basis! (" + this.toHexString() + ")");
    }
    if (exponent.sign < 0) {
        /* istanbul ignore next */
        throw Error("Negative exponent! (" + exponent.toHexString() + ")");
    }
    if (modulus.sign <= 0) {
        /* istanbul ignore next */
        throw Error("Non-positive modulus! (" + modulus.toHexString() + ")");
    }

    // 0^x mod 1 = 0 for every x >= 0 is a special case.
    if (modulus.equals(LargeInteger.ONE)) {
        return LargeInteger.ZERO;
    }

    // g^0 mod x = 1 if x > 1.
    if (exponent.sign === 0) {
        return LargeInteger.ONE;
    }

    var b = this.value;
    var g = b;
    var e = exponent.value;
    var m = modulus.value;

    if (b.length > m.length) {
        g = this.divQR(modulus)[1].value;
        li.resize(g, m.length);
    } else if (b.length < m.length) {
        g = li.newarray(m.length);
        li.set(g, b);
    }

    // Destination of final result.
    var w = li.newarray(m.length);

    if (naive) {
        li.modpow_naive(w, g, e, m);
    } else {
        li.modpow(w, g, e, m);
    }

    if (li.iszero(w)) {
        return LargeInteger.ZERO;
    } else {
        li.normalize(w);
        return new LargeInteger(1, w);
    }
};

/**
 * @description Computes extended greatest common divisor.
 * @param other Other integer.
 * @return Array [a, b, v] such that a * this + b * other = v and v is
 * the greatest common divisor of this and other.
 * @method
 */
LargeInteger.prototype.egcd = function (other) {
    var len = Math.max(this.length, other.length) + 1;

    var a = new LargeInteger(len);
    var b = new LargeInteger(len);
    var v = new LargeInteger(len);

    sli.egcd(a, b, v, this, other);

    sli.normalize(a);
    sli.normalize(b);
    sli.normalize(v);

    return [a, b, v];
};

/**
 * @description Computes modular inverse of this integer modulo the
 * input prime.
 * @param prime Odd positive prime integer.
 * @return Integer x such that x * this = 1 mod prime, where 0 <= x <
 * prime.
 * @method
 */
LargeInteger.prototype.modInv = function (prime) {

    // There is no need to optimize this by using a stripped extended
    // greatest common divisor algorithm.
    var a = this.egcd(prime)[0];
    if (a.sign < 0) {
        return prime.add(a);
    } else {
        return a;
    }
};

/**
 * @description Returns (this | prime), i.e., the Legendre symbol of
 * this modulo prime for an odd prime prime. (This is essentially a
 * GCD algorithm that keeps track of the symbol.)
 * @param prime An odd prime modulus.
 * @return Legendre symbol of this instance modulo the input.
 * @method
 */
LargeInteger.prototype.legendre = function (prime) {
    return sli.legendre(this.mod(prime), prime);
};

/**
 * @description Returns a square root of this integer modulo an odd
 * prime, where this integer is a quadratic residue modulo the prime.
 * @param prime An odd prime modulus.
 * @return Square root of this integer modulo the input odd prime.
 * @method
 */
LargeInteger.prototype.modSqrt = function (prime) {
    var res = new LargeInteger(prime.length);
    sli.modsqrt(res, this, prime);
    sli.normalize(res);
    return res;
};

/**
 * @description Returns the bits between the start index and end index
 * as an integer.
 * @param start Inclusive start index.
 * @param end Exclusive end index.
 * @return Bits between the start index and end index as an integer.
 * @method
 */
LargeInteger.prototype.slice = function (start, end) {
    var value = li.slice(this.value, start, end);
    var sign = this.sign;
    if (li.iszero(value)) {
        sign = 0;
    }
    return new LargeInteger(sign, value);
};

/**
 * @description Computes a byte array that represents the absolute
 * value of this integer. The parameter can be used to truncate the
 * most significant bytes or to ensure that a given number of bytes
 * are used, effectively padding the representation with zeros.
 * @param byteSize Number of bytes used in output.
 * @return Resulting array.
 * @method
 */
LargeInteger.prototype.toByteArray = function (byteSize) {
    var MASK_TOP_8 = 0x80;

    // Convert the representation with li.WORDSIZE words into a
    // representation with 8-bit words.
    var dense = util.change_wordsize(this.value, li.WORDSIZE, 8);

    if (typeof byteSize === "undefined") {

        // Remove or add as many leading bytes as needed.
        li.normalize(dense, MASK_TOP_8);
    } else {

        // Reduce/increase the number of bytes as requested.
        li.resize(dense, byteSize);
    }
    return dense.reverse();
};

/**
 * @description Computes a byte tree representation of this integer.
 * @return Byte tree representation of this integer.
 * @method
 */
LargeInteger.prototype.toByteTree = function () {
    return new verificatum.eio.ByteTree(this.toByteArray());
};

/**
 * @description Computes a hexadecimal representation of this integer.
 * @return Hexadecimal representation of this integer.
 * @method
 */
LargeInteger.prototype.toHexString = function () {
    return sli.hex(this);
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
LargeInteger.INSECURErandom = function (bitLength) {               // DEBUG
    var x = sli.INSECURErandom(bitLength);                         // DEBUG
    return new LargeInteger(x.sign, x.value);                      // DEBUG
};                                                                 // DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUG   THIS MUST ONLY USED FOR DEBUGGING PURPOSES     DEBUGDEBU// DEBUG
// DEBUG                                                  DEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
// DEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBUGDEBU// DEBUG
