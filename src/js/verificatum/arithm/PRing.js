
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
// ################### PRing ############################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description Ring of prime characteristic.
 * @class
 * @abstract
 * @memberof verificatum.arithm
 */
function PRing() {
};
PRing.prototype = Object.create(ArithmObject.prototype);
PRing.prototype.constructor = PRing;

/* istanbul ignore next */
/**
 * @description Returns the underlying prime order field.
 * @return Underlying prime order field.
 * @method
 */
PRing.prototype.getPField = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Compares this ring and the input ring.
 * @param other Other instance of subclass of this class.
 * @return true or false depending on if this ring equals the
 * other. This is based on deep comparison of content.
 * @method
 */
PRing.prototype.equals = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Zero of the this ring.
 * @return Zero of this ring.
 * @method
 */
PRing.prototype.getZERO = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Unit element of this ring.
 * @return Unit element of this ring.
 * @method
 */
PRing.prototype.getONE = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Number of random bytes needed to derive a random
 * element with the given statistical distance to uniform.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Number of random bytes needed to derive a random element.
 * @method
 */
PRing.prototype.randomElementByteLength = function (statDist) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Generates a random element in the ring.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Randomly chosen element from the ring.
 * @method
 */
PRing.prototype.randomElement = function (randomSource, statDist) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Recovers an element from the input byte tree.
 * @param byteTree Byte tree representation of an element.
 * @return Element represented by the byte tree.
 * @method
 */
PRing.prototype.toElement = function (byteTree) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Fixed number of bytes needed to represent a ring
 * element.
 * @return Fixed number of bytes used to represent ring elements.
 * @method
 */
PRing.prototype.getByteLength = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Fixed number of bytes that can be encoded into a ring
 * element.
 * @return Fixed number of bytes that can be encoded into a ring
 * element.
 * @method
 */
PRing.prototype.getEncodeLength = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Compiles a human readable representation of this field.
 * @return Human readable representation of this field.
 * @method
 */
PRing.prototype.toString = function () {
    throw new Error("Abstract method!");
};

// ######################################################################
// ################### PRingElement #####################################
// ######################################################################

/**
 * @description Element of ring of {@link verificatum.arithm.PRing}.
 * @class
 * @abstract
 * @memberof verificatum.arithm
 */
function PRingElement(pRing) {
    this.pRing = pRing;
};
PRingElement.prototype = Object.create(ArithmObject.prototype);
PRingElement.prototype.constructor = PRingElement;

/**
 * @description Throws an error if this and the input are not
 * instances of the same class and are contained in the same ring.
 * @param other Other element expected to be contained in the same
 * ring.
 * @method
 */
PRingElement.prototype.assertType = function (other) {
    if (other.getName() !== this.getName()) {
        throw Error("Element of wrong class! (" +
                    other.getName() + " != " + this.getName() + ")");
    }
    if (!this.pRing.equals(other.pRing)) {
        throw Error("Distinct rings");
    }
};

/**
 * @description Returns the ring containing this element.
 * @return Ring containing this element.
 * @method
 */
PRingElement.prototype.getPRing = function () {
    return this.pRing;
};

/* istanbul ignore next */
/**
 * @description Compares this element and the input.
 * @param other Other ring element.
 * @return true or false depending on if this element equals the input
 * or not.
 * @method
 */
PRingElement.prototype.equals = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Returns the negative of this element.
 * @return Negative of this element.
 * @method
 */
PRingElement.prototype.neg = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes product of this element and the input. If the
 * input belongs to the ring of exponents to which this element
 * belongs, then we multiply each component of this element with each
 * component of the input, and otherwise we simply multiply each
 * component of this element by the input directly.
 * @param other Other ring element or integer.
 * @return this * other.
 * @method
 */
PRingElement.prototype.mul = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes the sum of this element and the input.
 * @param other Other ring element from the same ring as this element.
 * @return this + other.
 * @method
 */
PRingElement.prototype.add = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes the difference of this element and the input.
 * @param other Other ring element from the same ring as this element.
 * @return this - other.
 * @method
 */
PRingElement.prototype.sub = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Returns the multiplicative inverse of this element.
 * @return Multiplicative inverse of this element.
 * @method
 */
PRingElement.prototype.inv = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes a byte tree representation of this element.
 * @return Byte tree representation of this element.
 * @method
 */
PRingElement.prototype.toByteTree = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Compiles a human readable representation of this
 * element. This should only be used for debugging.
 * @return Human readable representation of this element.
 * @method
 */
PRingElement.prototype.toString = function () {
    throw new Error("Abstract method!");
};
/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */
