
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

// ######################################################################
// ################### PPRingElement ####################################
// ######################################################################
// This code becomes more complex using map, some, etc without any
// gain in speed.

/**
 * @description Element of product ring over prime order fields.
 * @class
 * @extends verificatum.arithm.PRing
 * @memberof verificatum.arithm
 */
function PPRingElement(pPRing, values) {
    PRingElement.call(this, pPRing);
    this.values = values;
};
PPRingElement.prototype = Object.create(PRingElement.prototype);
PPRingElement.prototype.constructor = PPRingElement;

PPRingElement.prototype.equals = function (other) {
    this.assertType(other);
    for (var i = 0; i < this.values.length; i++) {
        if (!this.values[i].equals(other.values[i])) {
            return false;
        }
    }
    return true;
};

PPRingElement.prototype.add = function (other) {
    this.assertType(other);
    var values = [];
    for (var i = 0; i < this.values.length; i++) {
        values[i] = this.values[i].add(other.values[i]);
    }
    return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.sub = function (other) {
    this.assertType(other);
    var values = [];
    for (var i = 0; i < this.values.length; i++) {
        values[i] = this.values[i].sub(other.values[i]);
    }
    return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.neg = function () {
    var values = [];
    for (var i = 0; i < this.values.length; i++) {
        values[i] = this.values[i].neg();
    }
    return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.mul = function (other) {
    var i;
    var values = [];
    if (this.pRing.equals(other.pRing)) {
        for (i = 0; i < this.values.length; i++) {
            values[i] = this.values[i].mul(other.values[i]);
        }
    } else {
        for (i = 0; i < this.values.length; i++) {
            values[i] = this.values[i].mul(other);
        }
    }
    return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.inv = function () {
    var values = [];
    for (var i = 0; i < this.values.length; i++) {
        values[i] = this.values[i].inv();
    }
    return new PPRingElement(this.pRing, values);
};

PPRingElement.prototype.toByteTree = function () {
    var children = [];
    for (var i = 0; i < this.values.length; i++) {
        children[i] = this.values[i].toByteTree();
    }
    return new verificatum.eio.ByteTree(children);
};

PPRingElement.prototype.toString = function () {
    var s = "";
    for (var i = 0; i < this.values.length; i++) {
        s += "," + this.values[i].toString();
    }
    return "(" + s.slice(1) + ")";
};

/**
 * @description ith component of this product ring element.
 * @param i Index of component.
 * @return ith component of this product ring element.
 * @method
 */
PPRingElement.prototype.project = function (i) {
    return this.values[i];
};


// ######################################################################
// ################### PPRing ###########################################
// ######################################################################

/**
 * @description Product ring over prime order fields.
 * @class
 * @extends verificatum.arithm.PRing
 * @memberof verificatum.arithm
 */
function PPRing(value, width) {
    PRing.call(this);

    var values;
    var i;

    if (verificatum.util.ofType(value, "array")) {
        this.pRings = value;
    } else {
        this.pRings = verificatum.util.full(value, width);
    }

    values = [];
    for (i = 0; i < this.pRings.length; i++) {
        values[i] = this.pRings[i].getZERO();
    }
    this.ZERO = new PPRingElement(this, values);

    values = [];
    for (i = 0; i < this.pRings.length; i++) {
        values[i] = this.pRings[i].getONE();
    }
    this.ONE = new PPRingElement(this, values);
    this.byteLength = this.ONE.toByteTree().toByteArray().length;
};
PPRing.prototype = Object.create(PRing.prototype);
PPRing.prototype.constructor = PPRing;

PPRing.prototype.getPField = function () {
    return this.pRings[0].getPField();
};

PPRing.prototype.equals = function (other) {
    if (this === other) {
        return true;
    }
    if (other.getName() !== "PPRing") {
        return false;
    }
    if (this.pRings.length !== other.pRings.length) {
        return false;
    }
    for (var i = 0; i < this.pRings.length; i++) {
        if (!this.pRings[i].equals(other.pRings[i])) {
            return false;
        }
    }
    return true;
};

PPRing.prototype.getZERO = function () {
    return this.ZERO;
};

PPRing.prototype.getONE = function () {
    return this.ONE;
};

PPRing.prototype.randomElementByteLength = function (statDist) {
    var byteLength = 0;
    for (var i = 0; i < this.pRings.length; i++) {
        byteLength += this.pRings[i].randomElementByteLength(statDist);
    }
    return byteLength;
};

PPRing.prototype.randomElement = function (randomSource, statDist) {
    var values = [];
    for (var i = 0; i < this.pRings.length; i++) {
        values[i] = this.pRings[i].randomElement(randomSource, statDist);
    }
    return new PPRingElement(this, values);
};

PPRing.prototype.toElement = function (byteTree) {
    if (!byteTree.isLeaf() ||
        byteTree.value.length === this.pRings.length) {

        var children = [];
        for (var i = 0; i < this.pRings.length; i++) {
            children[i] = this.pRings[i].toElement(byteTree.value[i]);
        }
        return new PPRingElement(this, children);
    } else {
        throw Error("Input byte tree does not represent an element!");
    }
};

PPRing.prototype.getByteLength = function () {
    return this.byteLength;
};

PPRing.prototype.getEncodeLength = function () {
    return Math.floor((this.order.bitLength() + 1) / 8);
};

PPRing.prototype.toString = function () {
    var s = "";
    for (var i = 0; i < this.pRings.length; i++) {
        s += "," + this.pRings[i].toString();
    }
    return "(" + s.slice(1) + ")";
};

/**
 * @description Product width of this ring.
 * @return Product width of this ring.
 * @method
 */
PPRing.prototype.getWidth = function () {
    return this.pRings.length;
};

/**
 * @description ith component of this product ring.
 * @return ith component of this product ring.
 * @method
 */
PPRing.prototype.project = function (i) {
    return this.pRings[i];
};

/**
 * @description Forms a product element formed from the given list of
 * elements which are required to belong to the corresponding
 * components of this ring, or from a single element from the
 * underlying ring (in which case it is simply repeated). The latter
 * case requires that the product ring is formed from identical
 * components.
 * @return Product element formed from the inputs.
 * @method
 */
PPRing.prototype.prod = function (value) {
    var i;
    var elements;

    // List of elements.
    if (verificatum.util.ofType(value, "array")) {
        if (value.length === this.pRings.length) {
            elements = value;
        } else {
            throw Error("Wrong number of elements! (" +
                        elements.length + " != " + this.pRings.length + ")");
        }
        // Repeated element.
    } else {
        elements = [];
        for (i = 0; i < this.pRings.length; i++) {
            elements[i] = value;
        }
    }
    for (i = 0; i < this.pRings.length; i++) {
        if (!elements[i].pRing.equals(this.pRings[i])) {
            throw Error("Element " + i + " belongs to the wrong subring!");
        }
    }
    return new PPRingElement(this, elements);
};
