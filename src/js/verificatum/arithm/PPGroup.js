
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

M4_NEEDS(verificatum/arithm/PGroup.js)dnl

// ######################################################################
// ################### PPGroupElement ###################################
// ######################################################################
// This code becomes more complex using map, some, etc without any
// gain in speed.

/**
 * @description Element of {@link verificatum.arithm.PPGroup}.
 * @class
 * @extends verificatum.arithm.PGroupElement
 * @memberof verificatum.arithm
 */
function PPGroupElement(pPGroup, values) {
    PGroupElement.call(this, pPGroup);
    this.values = values;
};
PPGroupElement.prototype = Object.create(PGroupElement.prototype);
PPGroupElement.prototype.constructor = PPGroupElement;

PPGroupElement.prototype.equals = function (other) {
    this.assertType(other);
    for (var i = 0; i < this.values.length; i++) {
        if (!this.values[i].equals(other.values[i])) {
            return false;
        }
    }
    return true;
};

PPGroupElement.prototype.mul = function (other) {
    this.assertType(other);
    var values = [];
    for (var i = 0; i < this.values.length; i++) {
        values[i] = this.values[i].mul(other.values[i]);
    }
    return new PPGroupElement(this.pGroup, values);
};

PPGroupElement.prototype.exp = function (exponent) {
    var i;
    var values = [];

    if (exponent.getName() === "PPRingElement" &&
        exponent.pRing.equals(this.pGroup.pRing)) {

        for (i = 0; i < this.values.length; i++) {
            values[i] = this.values[i].exp(exponent.values[i]);
        }
    } else {
        for (i = 0; i < this.values.length; i++) {
            values[i] = this.values[i].exp(exponent);
        }
    }
    return new PPGroupElement(this.pGroup, values);
};

PPGroupElement.prototype.inv = function () {
    var values = [];
    for (var i = 0; i < this.values.length; i++) {
        values[i] = this.values[i].inv();
    }
    return new PPGroupElement(this.pGroup, values);
};

PPGroupElement.prototype.toByteTree = function () {
    var children = [];
    for (var i = 0; i < this.values.length; i++) {
        children[i] = this.values[i].toByteTree();
    }
    return new verificatum.eio.ByteTree(children);
};

PPGroupElement.prototype.toString = function () {
    var s = "";
    for (var i = 0; i < this.values.length; i++) {
        s += "," + this.values[i].toString();
    }
    return "(" + s.slice(1) + ")";
};

/**
 * @description ith component of this product group element.
 * @param i Index of component.
 * @return ith component of this product group element.
 * @method
 */
PPGroupElement.prototype.project = function (i) {
    return this.values[i];
};

PPGroupElement.prototype.decode = function (destination, startIndex) {
    var origStartIndex = startIndex;
    for (var i = 0; i < this.values.length; i++) {
        startIndex += this.values[i].decode(destination, startIndex);
    }
    return startIndex - origStartIndex;
};


// ######################################################################
// ################### PPGroup ##########################################
// ######################################################################

// Generates the product ring of the product group formed of the list
// of groups.
var genPRing = function (value) {
    if (verificatum.util.ofType(value, "array")) {
        var pRings = [];
        for (var i = 0; i < value.length; i++) {
            pRings[i] = value[i].pRing;
        }
        return new PPRing(pRings);
    } else {
        return value;
    }
};

/**
 * @description Product group of groups where all non-trivial elements
 * have identical odd prime orders.
 * @class
 * @extends verificatum.arithm.PGroup
 * @memberof verificatum.arithm
 */
function PPGroup(value, width) {
    PGroup.call(this, genPRing(verificatum.util.full(value, width)));

    var values;
    var i;

    if (verificatum.util.ofType(value, "array")) {
        this.pGroups = value;
    } else {
        this.pGroups = verificatum.util.full(value, width);
    }

    this.encodeLength = 0;
    for (i = 0; i < this.pGroups.length; i++) {
        this.encodeLength += this.pGroups[i].encodeLength;
    }

    values = [];
    for (i = 0; i < this.pGroups.length; i++) {
        values[i] = this.pGroups[i].getg();
    }
    this.generator = new PPGroupElement(this, values);

    values = [];
    for (i = 0; i < this.pGroups.length; i++) {
        values[i] = this.pGroups[i].getONE();
    }
    this.ONE = new PPGroupElement(this, values);
    this.byteLength = this.ONE.toByteTree().toByteArray().length;
};
PPGroup.prototype = Object.create(PGroup.prototype);
PPGroup.prototype.constructor = PPGroup;

PGroup.prototype.getPrimeOrderPGroup = function () {
    return this.pGroups[0].getPrimeOrderPGroup();
};

PPGroup.prototype.equals = function (other) {
    if (this === other) {
        return true;
    }
    if (other.getName() !== "PPGroup") {
        return false;
    }
    if (this.pGroups.length !== other.pGroups.length) {
        return false;
    }
    for (var i = 0; i < this.pGroups.length; i++) {
        if (!this.pGroups[i].equals(other.pGroups[i])) {
            return false;
        }
    }
    return true;
};

/**
 * @description Returns the width, i.e., the number of groups from
 * which this product group is formed.
 * @return Width of product.
 * @method
 */
PPGroup.prototype.getWidth = function () {
    return this.pGroups.length;
};

/**
 * @description Returns ith factor of this product group.
 * @param i Index of factor to return.
 * @return Factor of this product group.
 * @method
 */
PPGroup.prototype.project = function (i) {
    return this.pGroups[i];
};

/**
 * @description Returns an element of this group formed from elements
 * of its factor groups.
 * @param value Array of elements from the factor groups of this
 * product group, or a single element, in which case it is assumed
 * that this group is a power of a single group.
 * @return Element of this group.
 * @return Factor of this product group.
 * @method
 */
PPGroup.prototype.prod = function (value) {
    var i;
    var elements;

    // List of elements.
    if (verificatum.util.ofType(value, "array")) {
        if (value.length === this.pGroups.length) {
            elements = value;
        } else {
            throw Error("Wrong number of elements! (" +
                        value.length + " != " + this.pGroups.length + ")");
        }
        // Repeated element.
    } else {
        elements = [];
        for (i = 0; i < this.pGroups.length; i++) {
            elements[i] = value;
        }
    }
    for (i = 0; i < this.pGroups.length; i++) {
        if (!elements[i].pGroup.equals(this.pGroups[i])) {
            throw Error("Element " + i + " belongs to the wrong group!");
        }
    }
    return new PPGroupElement(this, elements);
};

PPGroup.prototype.getElementOrder = function () {
    return this.pGroups[0].getElementOrder();
};

PPGroup.prototype.getg = function () {
    return this.generator;
};

PPGroup.prototype.getONE = function () {
    return this.ONE;
};

PPGroup.prototype.randomElement = function (randomSource, statDist) {
    var values = [];
    for (var i = 0; i < this.pGroups.length; i++) {
        values[i] = this.pGroups[i].randomElement(randomSource, statDist);
    }
    return new PPGroupElement(this, values);
};

PPGroup.prototype.toElement = function (byteTree) {
    if (!byteTree.isLeaf() ||
        byteTree.value.length === this.pGroups.length) {

        var children = [];
        for (var i = 0; i < this.pGroups.length; i++) {
            children[i] = this.pGroups[i].toElement(byteTree.value[i]);
        }
        return new PPGroupElement(this, children);
    } else {
        throw Error("Input byte tree does not represent an element!");
    }
};

PPGroup.prototype.getByteLength = function () {
    return this.byteLength;
};

PPGroup.prototype.toString = function () {
    var s = "";
    for (var i = 0; i < this.pGroups.length; i++) {
        s += "," + this.pGroups[i].toString();
    }
    return "(" + s.slice(1) + ")";
};

PPGroup.prototype.encode = function (bytes, startIndex, length) {
    var elements = [];
    for (var i = 0; i < this.pGroups.length; i++) {
        var len = Math.min(length, this.pGroups[i].encodeLength);
        elements[i] = this.pGroups[i].encode(bytes, startIndex, len);
        startIndex += len;
        length -= len;
    }
    return new PPGroupElement(this, elements);
};

PPGroup.prototype.randomElement = function (randomSource, statDist) {
    var elements = [];
    for (var i = 0; i < this.pGroups.length; i++) {
        elements[i] = this.pGroups[i].randomElement(randomSource, statDist);
    }
    return new PPGroupElement(this, elements);
};

/**
 * @description Recovers a PPGroup instance from its representation
 * as a byte tree.
 * @param byteTree Byte tree representation of a PPGroup instance.
 * @return Instance of PPGroup.
 * @function fromByteTree
 * @memberof verificatum.arithm.PPGroup
 */
PPGroup.fromByteTree = function (byteTree) {
    if (byteTree.isLeaf() || byteTree.value.length !== 2) {
        throw Error("Invalid representation of a group!");
    }
    var atomicPGroups = PPGroup.atomicPGroups(byteTree.value[0]);
    return PPGroup.fromStructure(byteTree.value[1], atomicPGroups);
};

// Recovers atomic PGroups.
PPGroup.atomicPGroups = function (byteTree) {
    if (byteTree.isLeaf() || byteTree.value.length === 0) {
        throw Error("Invalid representation of atomic groups!");
    }
    var pGroups = [];
    for (var i = 0; i < byteTree.value.length; i++) {
        pGroups[i] = PGroup.unmarshal(byteTree.value[i]);
    }
    return pGroups;
};

// Recovers PGroup from a structure and an array of atomic groups.
PPGroup.fromStructure = function (byteTree, atomicPGroups) {
    if (byteTree.isLeaf()) {
        if (byteTree.value.length !== 4) {
            throw Error("Leaf does not contain an index!");
        }
        var index = verificatum.util.readUint32FromByteArray(byteTree.value);
        if (index >= 0 && index < byteTree.value.length) {
            return atomicPGroups[index];
        } else {
            throw Error("Index out of range!");
        }
    } else {
        var bts = [];
        for (var i = 0; i < byteTree.value.length; i++) {
            bts[i] = PPGroup.fromStructure(byteTree.value[i], atomicPGroups);
        }
        return new verificatum.arithm.PPGroup(bts);
    }
};
