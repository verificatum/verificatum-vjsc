
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

M4_NEEDS(verificatum/arithm/PRing.js)dnl
M4_NEEDS(verificatum/arithm/LargeInteger.js)dnl

// ######################################################################
// ################### PFieldElement ####################################
// ######################################################################

/**
 * @description Element of {@link verificatum.arithm.PField}.
 * @class
 * @extends verificatum.arithm.PRingElement
 * @memberof verificatum.arithm
 */
function PFieldElement(pField, value) {
    PRingElement.call(this, pField);
    this.value = value;
};
PFieldElement.prototype = Object.create(PRingElement.prototype);
PFieldElement.prototype.constructor = PFieldElement;

PFieldElement.prototype.equals = function (other) {
    this.assertType(other);
    return this.value.cmp(other.value) === 0;
};

PFieldElement.prototype.neg = function () {
    return new PFieldElement(this.pRing, this.pRing.order.sub(this.value));
};

PFieldElement.prototype.mul = function (other) {
    var v;
    if (util.ofType(other, PFieldElement)) {
        v = this.value.modMul(other.value, this.pRing.order);
    } else {
        v = this.value.modMul(other, this.pRing.order);
    }
    return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.add = function (other) {
    this.assertType(other);
    var v = this.value.modAdd(other.value, this.pRing.order);
    return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.sub = function (other) {
    this.assertType(other);
    var v = this.value.modSub(other.value, this.pRing.order);
    return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.inv = function () {
    var v = this.value.modInv(this.pRing.order);
    return new PFieldElement(this.pRing, v);
};

PFieldElement.prototype.toByteTree = function () {
    var byteLength = this.pRing.byteLength;
    return new verificatum.eio.ByteTree(this.value.toByteArray(byteLength));
};

PFieldElement.prototype.toString = function () {
    return this.value.toHexString();
};


// ######################################################################
// ################### PField ###########################################
// ######################################################################

/**
 * @description Prime order field.
 * @class
 * @extends verificatum.arithm.PRing
 * @memberof verificatum.arithm
 */
function PField(order) {
    PRing.call(this);
    if (typeof order === "number") {
        this.order = new LargeInteger(order.toString(16));
    } else if (util.ofType(order, "string")) {
        this.order = new LargeInteger(order);
    } else {
        this.order = order;
    }
    this.bitLength = this.order.bitLength();
    this.byteLength = this.order.toByteArray().length;
};
PField.prototype = Object.create(PRing.prototype);
PField.prototype.constructor = PField;

PField.prototype.getPField = function () {
    return this;
};

PField.prototype.equals = function (other) {
    if (this === other) {
        return true;
    }
    if (other.getName() !== "PField") {
        return false;
    }
    return this.order.equals(other.order);
};

PField.prototype.getZERO = function () {
    return new PFieldElement(this, LargeInteger.ZERO);
};

PField.prototype.getONE = function () {
    return new PFieldElement(this, LargeInteger.ONE);
};

PField.prototype.randomElementByteLength = function (statDist) {
    return LargeInteger.byteLengthRandom(this.bitLength + statDist);
};

PField.prototype.randomElement = function (randomSource, statDist) {
    var r = new LargeInteger(this.bitLength + statDist, randomSource);
    return new PFieldElement(this, r.mod(this.order));
};

/**
 * @description Recovers an element from the input byte tree, or
 * directly from a raw byte array.
 * @param param Byte tree representation of an element, or a raw byte array.
 * @return Element represented by the input.
 * @method
 */
PField.prototype.toElement = function (param) {
    var integer;
    if (util.ofType(param, eio.ByteTree) &&
        param.isLeaf() &&
        param.value.length === this.getByteLength()) {
        integer = new LargeInteger(param.value);
    } else {
        integer = new LargeInteger(param);
    }
    return new PFieldElement(this, integer.mod(this.order));
};

PField.prototype.getByteLength = function () {
    return this.byteLength;
};

PField.prototype.getEncodeLength = function () {
    return Math.floor((this.order.bitLength() - 1) / 8);
};

PField.prototype.toString = function () {
    return this.order.toHexString();
};
