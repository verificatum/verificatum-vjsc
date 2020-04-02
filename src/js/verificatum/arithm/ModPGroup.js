
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

M4_NEEDS(verificatum/arithm/LargeInteger.js)dnl
M4_NEEDS(verificatum/arithm/PField.js)dnl
M4_NEEDS(verificatum/arithm/PGroup.js)dnl
M4_NEEDS(verificatum/arithm/ModPGroup_named_groups.js)dnl

// ######################################################################
// ################### ModPGroupElement #################################
// ######################################################################

/**
 * @description Element of {@link verificatum.arithm.ModPGroup}.
 * @class
 * @extends verificatum.arithm.PGroupElement
 * @memberof verificatum.arithm
 */
function ModPGroupElement(pGroup, value) {
    PGroupElement.call(this);
    this.pGroup = pGroup;
    this.value = value;
};
ModPGroupElement.prototype = Object.create(PGroupElement.prototype);
ModPGroupElement.prototype.constructor = ModPGroupElement;

ModPGroupElement.prototype.equals = function (other) {
    this.assertType(other);
    return this.value.equals(other.value);
};

ModPGroupElement.prototype.mul = function (factor) {
    this.assertType(factor);
    var value = this.value.mul(factor.value).mod(this.pGroup.modulus);
    return new ModPGroupElement(this.pGroup, value);
};

M4_IFN_INCLUDED(verificatum/arithm/FixModPow.js)dnl
ModPGroupElement.prototype.exp = function (exponent) {
    if (exponent.constructor === PFieldElement) {
        exponent = exponent.value;
    }
    var value = this.value.modPow(exponent, this.pGroup.modulus);
    return new ModPGroupElement(this.pGroup, value);
};
M4_FIN_INCLUDED(verificatum/arithm/FixModPow.js)dnl

M4_IF_INCLUDED(verificatum/arithm/FixModPow.js)dnl
ModPGroupElement.prototype.fixed = function (exponentiations) {
    this.fixExp =
        new FixModPow(this.value, this.pGroup.modulus, exponentiations);
};

ModPGroupElement.prototype.exp = function (exponent) {
    this.expCounter++;
    if (exponent.constructor === PFieldElement) {
        exponent = exponent.value;
    }

    // Generic exponentiation.
    if (this.fixExp === null) {

        var value = this.value.modPow(exponent, this.pGroup.modulus);
        return new ModPGroupElement(this.pGroup, value);

        // Fixed-basis exponentiation.
    } else {
        return new ModPGroupElement(this.pGroup, this.fixExp.modPow(exponent));
    }
};
M4_FI_INCLUDED(verificatum/arithm/FixModPow.js)dnl

ModPGroupElement.prototype.inv = function () {
    var invValue = this.value.modInv(this.pGroup.modulus);
    return new ModPGroupElement(this.pGroup, invValue);
};

ModPGroupElement.prototype.toByteTree = function () {
    var byteArray = this.value.toByteArray(this.pGroup.modulusByteLength);
    return new eio.ByteTree(byteArray);
};

ModPGroupElement.prototype.toString = function () {
    return this.value.toHexString();
};


// ######################################################################
// ################### ModPGroup ########################################
// ######################################################################

/**
 * @description Multiplicative group modulo a prime.
 * @class
 * @extends verificatum.arithm.PGroup
 * @memberof verificatum.arithm
 */
function ModPGroup(modulus, order, gi, encoding) {
    PGroup.call(this, ModPGroup.genPField(modulus, order));
    if (typeof order === "undefined") {
        var params = ModPGroup.getParams(modulus);
        this.modulus = new LargeInteger(params[0]);
        gi = new LargeInteger(params[1]);
        this.encoding = 1;
    } else {
        this.modulus = modulus;
        this.encoding = encoding;
    }
    this.generator = new ModPGroupElement(this, gi);

    this.modulusByteLength = this.modulus.toByteArray().length;
    this.ONE = new ModPGroupElement(this, LargeInteger.ONE);

    // RO encoding.
    if (this.encoding === 0) {

        throw Error("RO encoding is not supported!");

        // Safe prime encoding.
    } else if (this.encoding === 1) {

        this.encodeLength = Math.floor((this.modulus.bitLength() - 2) / 8) - 4;

        // Subgroup encoding.
    } else if (this.encoding === 2) {

        throw Error("Subgroup encoding is not supported!");

    } else {
        throw new Error("Unsupported encoding! (" + this.encoding + ")");
    }
};
ModPGroup.prototype = Object.create(PGroup.prototype);
ModPGroup.prototype.constructor = ModPGroup;

ModPGroup.genPField = function (groupName, order) {
    if (typeof order === "undefined") {
        var params = ModPGroup.getParams(groupName);
        if (params.length < 4) {
            var modulus = new LargeInteger(params[0]);
            order = modulus.sub(LargeInteger.ONE).div(LargeInteger.TWO);
        } else {
            order = new LargeInteger(params[3]);
        }
    }
    return new PField(order);
};

/**
 * @description Recovers a ModPGroup instance from its representation
 * as a byte tree.
 * @param byteTree Byte tree representation of a ModPGroup instance.
 * @return Instance of ModPGroup.
 * @function fromByteTree
 * @memberof verificatum.arithm.ModPGroup
 */
ModPGroup.fromByteTree = function (byteTree) {
    if (byteTree.isLeaf()) {
        throw Error("Byte tree is a leaf, expected four children!");
    }
    if (byteTree.value.length !== 4) {
        throw Error("Wrong number of children! (" +
                    byteTree.value.length + " !== 4)");
    }
    var modulus = new LargeInteger(byteTree.value[0]);
    var order = new LargeInteger(byteTree.value[1]);
    var gi = new LargeInteger(byteTree.value[2]);

    byteTree = byteTree.value[3];
    if (!byteTree.isLeaf() || byteTree.value.length !== 4) {
        throw Error("Malformed encoding number!");
    }
    var encoding = util.readUint32FromByteArray(byteTree.value);
    if (encoding >= 4) {
        throw Error("Unsupported encoding number!");
    }

    return new ModPGroup(modulus, order, gi, encoding);
};

/**
 * @description Returns an array of all names of available
 * multiplicative groups.
 * @return Array of all names of available multiplicative groups.
 * @function getPGroupNames
 * @memberof verificatum.arithm.ModPGroup
 */
ModPGroup.getPGroupNames = function () {
    return Object.keys(ModPGroup.named_groups);
};

/**
 * @description Returns the group with the given name.
 * @return Named group.
 * @function getPGroup
 * @memberof verificatum.arithm.ModPGroup
 */
ModPGroup.getPGroup = function (groupName) {
    var params = ModPGroup.named_groups[groupName];
    if (typeof params === "undefined") {
        return null;
    } else {
        return new ModPGroup(groupName);
    }
};

/**
 * @description Returns an array of all available multiplicative groups.
 * @return Array of all available multiplicative groups.
 * @function getPGroups
 * @memberof verificatum.arithm.ModPGroup
 */
ModPGroup.getPGroups = function () {
    var pGroupNames = ModPGroup.getPGroupNames();
    var pGroups = [];
    for (var i = 0; i < pGroupNames.length; i++) {
        pGroups[i] = new ModPGroup(pGroupNames[i]);
    }
    return pGroups;
};

dnl Table of parameters of named standard curves.
    M4_INCLUDE(verificatum/arithm/ModPGroup_named_groups.js)dnl

ModPGroup.getParams = function (groupName) {
    var params = ModPGroup.named_groups[groupName];
    if (typeof params === "undefined") {
        throw Error("Unknown group name! (" + groupName + ")");
    } else {
        return params;
    }
};

ModPGroup.prototype.getPrimeOrderPGroup = function () {
    return this;
};

ModPGroup.prototype.equals = function (other) {
    if (this === other) {
        return true;
    }
    if (other.getName() !== "ModPGroup") {
        return false;
    }
    return this.modulus.equals(other.modulus) &&
        this.generator.equals(other.generator) &&
        this.encoding === other.encoding;
};

ModPGroup.prototype.getElementOrder = function () {
    return this.pRing.order;
};

ModPGroup.prototype.getg = function () {
    return this.generator;
};

ModPGroup.prototype.getONE = function () {
    return this.ONE;
};

ModPGroup.prototype.toElement = function (byteTree) {
    if (!byteTree.isLeaf()) {
        throw Error("Byte tree is not a leaf!");
    }
    if (byteTree.value.length !== this.modulusByteLength) {
        throw Error("Wrong number of bytes! (" +
                    byteTree.value.length + " = " +
                    this.modulusByteLength + ")");
    }
    var value = new LargeInteger(byteTree.value);

    if (this.modulus.cmp(value) <= 0) {
        throw Error("Integer representative not canonically reduced!");
    }
    return new ModPGroupElement(this, value);
};

ModPGroup.prototype.encode = function (bytes, startIndex, length) {
    var elen = this.encodeLength;

    if (length > elen) {
        throw Error("Input is too long! (" + length + " > " + elen + ")");
    }

    // Make room for a leading integer and data.
    var bytesToUse = [];
    bytesToUse.length = elen + 4;

    // Write length of data.
    verificatum.util.setUint32ToByteArray(bytesToUse, length, 0);

    // Write data.
    var i = startIndex;
    var j = 4;
    while (j < length + 4) {
        bytesToUse[j] = bytes[i];
        i++;
        j++;
    }

    // Zero out the rest.
    while (j < bytesToUse.length) {
        bytesToUse[j] = 0;
        j++;
    }

    // Make sure value is non-zero. (Ignored during decoding due to
    // zero length.)
    if (length === 0) {
        bytesToUse[5] = 1;
    }

    // Negate if not a quadratic residue.
    var value = new LargeInteger(bytesToUse);
    if (value.legendre(this.modulus) !== 1) {
        value = this.modulus.sub(value);
    }
    return new ModPGroupElement(this, value);
};

ModPGroup.prototype.randomElement = function (randomSource, statDist) {
    var bits = 8 * this.modulusByteLength + statDist;
    var r = new LargeInteger(bits, randomSource);
    return new ModPGroupElement(this, r.mod(this.modulus));
};

ModPGroup.prototype.toString = function () {
    return this.modulus.toHexString() + ":" +
        this.getElementOrder().toHexString() + ":" +
        this.generator.toString() + ":encoding(" + this.encoding + ")";
};

PGroupElement.prototype.decode = function (destination, startIndex) {
    var i;
    var j;
    var val = this.pGroup.modulus.sub(this.value);
    if (this.value.cmp(val) < 0) {
        val = this.value;
    }
    var bytes = val.toByteArray();

    // Slice spurious bytes if any.
    var ulen = this.pGroup.encodeLength + 4;
    if (bytes.length > ulen) {
        bytes = bytes.slice(bytes.length - ulen);
    }

    // Add leading zero bytes if needed.
    if (bytes.length < ulen) {
        var raw = [];
        i = 0;
        while (i < ulen - bytes.length) {
            raw[i] = 0;
            i++;
        }
        j = 0;
        while (j < bytes.length) {
            raw[i] = bytes[j];
            i++;
            j++;
        }
        bytes = raw;
    }

    // Now we have exactly this.pGroup.encodeLength bytes.
    var len = verificatum.util.readUint32FromByteArray(bytes, 0);
    if (len < 0 || this.pGroup.encodeLength < len) {
        throw Error("Illegal length of data! (" + len + ")");
    }
    i = startIndex;
    j = 4;
    while (j < len + 4) {
        destination[i] = bytes[j];
        i++;
        j++;
    }
    return len;
};
