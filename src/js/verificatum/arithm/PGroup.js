
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
// ################### PGroup ###########################################
// ######################################################################

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description Abstract group where every non-trivial element has the
 * order determined by the input PRing. We stress that this is not
 * necessarily a prime order group. Each group has an associated ring
 * of exponents, i.e., an instance of {@link verificatum.arithm.PRing}.
 * @class
 * @abstract
 * @memberof verificatum.arithm
 */
function PGroup(pRing) {
    this.pRing = pRing;
};
PGroup.prototype = Object.create(ArithmObject.prototype);
PGroup.prototype.constructor = PGroup;

/* jshint ignore:start */
/* eslint-disable no-use-before-define */
/**
 * @description Returns the group with the given name.
 * @return Named group.
 * @function getPGroup
 * @memberof verificatum.arithm.PGroup
 */
PGroup.getPGroup = function (groupName) {
    var pGroup = ModPGroup.getPGroup(groupName);
    if (pGroup !== null) {
        return pGroup;
    }
    pGroup = ECqPGroup.getPGroup(groupName);
    if (pGroup !== null) {
        return pGroup;
    }
    throw Error("Unknown group name! (" + groupName + ")");
};
/* jshint ignore:end */
/* eslint-enable no-use-before-define */

/**
 * @description Returns a product group or the input group if the
 * given width equals one.
 * @param pGroup Basic group.
 * @param keyWidth Width of product group.
 * @return Input group or product group.
 * @method
 * @static
 */
PGroup.getWideGroup = function (pGroup, keyWidth) {
    if (keyWidth > 1) {
        return new verificatum.arithm.PPGroup(pGroup, keyWidth);
    } else {
        return pGroup;
    }
};

/* istanbul ignore next */
/**
 * @description Returns the prime order group on which this group is
 * defined.
 * @return Underlying prime order group.
 * @method
 */
PGroup.prototype.getPrimeOrderPGroup = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Compares this group and the input group.
 * @param other Other instance of subclass of this class.
 * @return true or false depending on if this group equals the
 * other. This is based on deep comparison of content.
 * @method
 */
PGroup.prototype.equals = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Order of every non-trivial element.
 * @return Order of every non-trivial element.
 * @method
 */
PGroup.prototype.getElementOrder = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Standard generator of this group. This is a generator
 * in the sense that every element in this group can be written on the
 * form g^x for an element x of the ring of exponents of this group.
 * @return Standard generator of this group.
 * @method
 */
PGroup.prototype.getg = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Unit element of this group.
 * @return Unit element of this group.
 * @method
 */
PGroup.prototype.getONE = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Recovers an element from the input byte tree.
 * @param byteTree Byte tree representation of an element.
 * @return Element represented by the byte tree.
 * @method
 */
PGroup.prototype.toElement = function (byteTree) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Encodes the input bytes as a group element.
 * @param bytes Bytes of content.
 * @param startIndex Starting position of data to be encoded.
 * @return Element constructed from the input byte array.
 * @method
 */
PGroup.prototype.encode = function (bytes, startIndex, length) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Generates a random element in the group.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Randomly chosen element from the group.
 * @method
 */
PGroup.prototype.randomElement = function (randomSource, statDist) {
    throw new Error("Abstract method!");
};

/**
 * @description Determines the number of bytes that can be encoded
 * into a group element.
 * @return Number of bytes that can be encoded into a group element.
 * @method
 */
PGroup.prototype.getEncodeLength = function () {
    return this.encodeLength;
};

/**
 * @description Executes a benchmark of exponentiation in this group,
 * potentially with fixed-basis.
 * @param minSamples Minimal number of samples.
 * @param exps Number of exponentiations to pre-compute for, or zero
 * if no pre-computation is done.
 * @param randomSource Source of randomness.
 * @return Average number of milliseconds per exponentiation.
 * @method
 */
PGroup.prototype.benchExp = function (minSamples, exps, randomSource) {
    var g = this.getg();
    var e = this.pRing.randomElement(randomSource, 50);
    g = g.exp(e);

    // If exps === 0, then we are not doing fixed-basis, and we set
    // exps to one.
    var fixed = exps > 0;
    exps = Math.max(1, exps);

    var start = util.time_ms();

    for (var i = 0; i < minSamples; i++) {

        if (fixed) {
            g.fixed(exps);
        }

        for (var j = 0; j < exps; j++) {
            e = this.pRing.randomElement(randomSource, 50);
            var y = g.exp(e);
        }
    }
    return (util.time_ms() - start) / (exps * minSamples);

};

/**
 * @description Executes a benchmark of fixed-basis exponentiation in
 * this group.
 * @param minSamples Minimal number of samples.
 * @param exps Lists of number of exponentiations.
 * @param randomSource Source of randomness.
 * @return Average number of milliseconds per exponentiation.
 * @method
 */
PGroup.prototype.benchFixExp = function (minSamples, exps, randomSource) {
    var results = [];
    for (var i = 0; i < exps.length; i++) {
        results[i] = this.benchExp(minSamples, exps[i], randomSource);
    }
    return results;
};

/**
 * @description Executes a benchmark of exponentiation in all named
 * groups.
 * @param minSamples Minimal number of samples.
 * @param randomSource Source of randomness.
 * @return Average number of milliseconds per exponentiation.
 * @method
 */
PGroup.benchExp = function (pGroups, minSamples, randomSource) {
    var results = [];
    for (var i = 0; i < pGroups.length; i++) {
        results[i] = pGroups[i].benchExp(minSamples, 0, randomSource);
    }
    return results;
};

/**
 * @description Executes a benchmark of exponentiation in all named
 * groups.
 * @param pGroups Benchmarked groups.
 * @param minSamples Minimal number of samples.
 * @param exps Lists of number of exponentiations.
 * @param randomSource Source of randomness.
 * @return Average number of milliseconds per exponentiation.
 * @method
 */
PGroup.benchFixExp = function (pGroups, minSamples, exps, randomSource) {
    var results = [];
    for (var i = 0; i < pGroups.length; i++) {
        results[i] = pGroups[i].benchFixExp(minSamples, exps, randomSource);
    }
    return results;
};


// ######################################################################
// ################### PGroupElement ####################################
// ######################################################################

/**
 * @description Abstract group representing an element of {@link
 * verificatum.arithm.PGroup}.
 * @param pGroup Group to which this element belongs.
 * @class
 * @abstract
 * @memberof verificatum.arithm
 */
function PGroupElement(pGroup) {
    this.pGroup = pGroup;
    this.fixExp = null;
    this.expCounter = 0;
};
PGroupElement.prototype = Object.create(ArithmObject.prototype);
PGroupElement.prototype.constructor = PGroupElement;

/**
 * @description Throws an error if this and the input are not
 * instances of the same class and are contained in the same group.
 * @param other Other element expected to be contained in the same
 * group.
 * @method
 */
PGroupElement.prototype.assertType = function (other) {
    if (other.getName() !== this.getName()) {
        throw Error("Element of wrong class! (" +
                    other.getName() + " != " + this.getName() + ")");
    }
    if (!this.pGroup.equals(other.pGroup)) {
        throw Error("Distinct groups!");
    }
};

/* istanbul ignore next */
/**
 * @description Compares this element and the input.
 * @param other Other group element.
 * @return true or false depending on if this element equals the input
 * or not.
 * @method
 */
PGroupElement.prototype.equals = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes the product of this element and the input.
 * @param other Other group element from the same group as this element.
 * @return this * other.
 * @method
 */
PGroupElement.prototype.mul = function (other) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes a power of this element. If the exponent
 * belongs to the ring of exponents of the group to which this element
 * belongs, then we use its component exponents for the corresponding
 * components of this element. If not, then we simply use the exponent
 * directly for each component of this element.
 * @return Power of this element raised to the input exponent.
 * @method
 */
PGroupElement.prototype.exp = function (exponent) {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Returns the inverse of this element.
 * @return Inverse of this element.
 * @method
 */
PGroupElement.prototype.inv = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes a byte tree representation of this element.
 * @return Byte tree representation of this element.
 * @method
 */
PGroupElement.prototype.toByteTree = function () {
    throw new Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Compiles a human readable representation of this
 * element. This should only be used for debugging.
 * @return Human readable representation of this element.
 * @method
 */
PGroupElement.prototype.toString = function () {
    throw new Error("Abstract method!");
};

/**
 * @description Decodes the contents of a group element.
 * @param destination Destination of decoded bytes.
 * @param startIndex Where to start writing in destination.
 * @return The number of decoded bytes.
 * @method
 */
PGroupElement.prototype.decode = function (destination, startIndex) {
    /* istanbul ignore next */
    throw new Error("Abstract method!");
};

/**
 * @description Peform pre-computations for the given number of
 * fixed-basis exponentiations.
 *
 * @param size Expected number of exponentiations to compute.
 * @method
 */
PGroupElement.prototype.fixed = function (exps) {
    // By default we do nothing.
};


/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */
