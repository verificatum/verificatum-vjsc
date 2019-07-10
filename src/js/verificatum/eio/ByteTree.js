
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

// ##################################################################
// ############### ByteTree #########################################
// ##################################################################

/**
 * @description Class for representing ordered trees of byte arrays. A
 * byte tree is represented as an array of bytes as follows.
 *
 * <ul>
 *
 * <li> A leaf holding a sequence of bytes B of length l is converted
 *      into a byte array T|L|B, where "|" denotes concatenation, T is
 *      a single byte equal to 1 indicating that this is a leaf, and L
 *      is a 32-bit signed integer representation of l.
 *
 * <li> A node holding children c_0,...,c_{l-1} is converted into a
 *      byte array T|L|C_0|...|C_{l-1}, where T is a single byte equal
 *      to 0 indicating that this is a node, L is a 32-bit unsigned
 *      integer representation of l and C_i is the representation of
 *      c_i as a byte array.
 *
 * </ul>
 *
 * @param value Data needed to construct a byte tree. This can
 * be: (1) an array of other byte trees that becomes siblings in the
 * new instance, (2) a raw byte array in which case the resulting
 * instance becomes a leaf, or (3) a hexadecimal string representing a
 * byte tree. The hexadecimal string may contain an ASCII encoded
 * prefix ending with "::", in which case it is discarded.
 * @return Byte tree containing the input data.
 * @class
 * @memberof verificatum.eio
 */
function ByteTree(value) {
    
    if (verificatum.util.ofType(value, "array")) {
        if (typeof value[0] === "number") {
            this.type = ByteTree.LEAF;
            this.value = value;
        } else {
            this.type = ByteTree.NODE;
            this.value = value;
        }

    } else if (verificatum.util.ofType(value, "string")) {

        // Strip comment if present.
        var start = value.indexOf("::");
        if (start > 0) {
            value = value.slice(start + 2);
        }

        // Recover byte tree from hex string.
        var array = util.hexToByteArray(value);
        var bt = ByteTree.readByteTreeFromByteArray(array);
        this.type = bt.type;
        this.value = bt.value;

    } else {
        throw Error("Unexpected type of input!");
    }
};

// These are internal constants.
ByteTree.LEAF = 1;
ByteTree.NODE = 0;

/**
 * @description Recovers a byte tree from its representation as a byte
 * array from the given source. If the second parameter is given, then
 * reading starts at this position and a pair is returned. If no
 * second parameter is given, then the byte tree is simply returned.
 * @param source Array holding a representation of a byte tree.
 * @param index Position in the array where reading starts.
 * @return Recovered byte tree.
 * @method
 */
ByteTree.readByteTreeFromByteArray = function (source, index) {
    var outputPair = true;
    if (typeof index === "undefined") {
        index = 0;
        outputPair = false;
    }
    var pair = ByteTree.readByteTreeFromByteArrayInner(source, index);

    if (outputPair) {
        return pair;
    } else {
        return pair[0];
    }
};

// This is an internal function.
ByteTree.readByteTreeFromByteArrayInner = function (source, index) {

    var origIndex = index;

    // Read type of byte tree.
    var type = source[index];
    if (type !== ByteTree.LEAF && type !== ByteTree.NODE) {
        throw Error("Unknown type! (" + type + ")");
    }
    index++;

    // Read number of bytes/children.
    var length = verificatum.util.readUint32FromByteArray(source, index);
    if (length <= 0) {
        throw Error("Non-positive length! (" + length + ")");
    }
    index += 4;

    var byteTree;

    if (type === ByteTree.LEAF) {

        if (index + length <= source.length) {

            var data = source.slice(index, index + length);
            index += length;
            byteTree = new ByteTree(data);

        } else {
            throw new Error("Unable to read data for leaf, missing bytes! (" +
                            "index = " + index + ", length = " + length + ")");
        }

    } else {

        var children = [];
        for (var i = 0; i < length; i++) {
            var pair = ByteTree.readByteTreeFromByteArrayInner(source, index);
            children.push(pair[0]);
            index += pair[1];
        }
        byteTree = new ByteTree(children);
    }
    return [byteTree, index - origIndex];
};

/**
 * @description Guarantees that the input is a byte tree.
 * @param value Byte tree or a byte array.
 * @return Input value if it is a byte tree and a leaf byte tree based
 * on the byte array otherwise.
 * @method
 */
ByteTree.asByteTree = function (value) {
    if (util.ofType(value, eio.ByteTree)) {
        return value;
    } else {
        return new eio.ByteTree(value);
    }
};

/**
 * @description Indicates if this byte tree is a leaf or not.
 * @return True or false depending on if this byte tree is a leaf or not.
 * @method
 */
ByteTree.prototype.isLeaf = function () {
    return this.type === ByteTree.LEAF;
};

/**
 * @description Computes the total number of bytes needed to represent
 * this byte tree as a byte array.
 * @return Number of bytes needed to store a byte array representation
 * of this byte tree.
 * @method
 */
ByteTree.prototype.size = function () {
    if (this.type === ByteTree.LEAF) {
        return 1 + 4 + this.value.length;
    } else if (this.type === ByteTree.NODE) {
        var size = 1 + 4;
        for (var i = 0; i < this.value.length; i++) {
            size += this.value[i].size();
        }
        return size;
    } else {
        throw Error("Unknown type! (" + this.type + ")");
    }
};

/**
 * @description Writes a byte tree representation of this byte tree to
 * the destination starting at the given index.
 * @param destination Destination of written bytes.
 * @param index Index of starting position.
 * @return Number of bytes written.
 * @method
 */
ByteTree.prototype.setToByteArray = function (destination, index) {
    if (this.type === ByteTree.LEAF) {

        destination[index] = ByteTree.LEAF;
        index++;

        verificatum.util.setUint32ToByteArray(destination,
                                              this.value.length,
                                              index);
        index += 4;

        var i = index;
        var j = 0;
        while (j < this.value.length) {
            destination[i] = this.value[j];
            i++;
            j++;
        }

        return 1 + 4 + this.value.length;

    } else {

        var origIndex = index;

        destination[index] = ByteTree.NODE;
        index++;

        verificatum.util.setUint32ToByteArray(destination,
                                              this.value.length,
                                              index);
        index += 4;

        for (var k = 0; k < this.value.length; k++) {
            index += this.value[k].setToByteArray(destination, index);
        }
        return index - origIndex;
    }
};

/**
 * @description Generates a representation of this byte tree as a byte
 * array.
 * @return Representation of this byte tree as a byte array.
 * @method
 */
ByteTree.prototype.toByteArray = function () {
    var array = [];
    this.setToByteArray(array, 0);
    return array;
};

/**
 * @description Generates hexadecimal representation of this byte
 * tree.
 * @return Hexadecimal representation of this byte tree.
 * @method
 */
ByteTree.prototype.toHexString = function () {
    var ba = this.toByteArray();
    return verificatum.util.byteArrayToHex(ba);
};

// This is an internal function.
/* istanbul ignore next */
ByteTree.prototype.toPrettyStringInner = function (indent) {

    if (this.type === ByteTree.LEAF) {

        return indent +
            "\"" + verificatum.util.byteArrayToHex(this.value) + "\"";

    } else if (this.type === ByteTree.NODE) {

        var s = indent + "[\n";
        for (var i = 0; i < this.value.length; i++) {
            if (i > 0) {
                s += ",\n";
            }
            s += this.value[i].toPrettyString(indent + "    ");
        }
        s += "\n" + indent + "]";
        return s;
        
    } else {
        throw Error("Unknown type! (" + this.type + ")");
    }
};

/* istanbul ignore next */
/**
 * @description Generates representation as a nested JSON list with
 * the leaves as hexadecimal string representations of the data in
 * leaves. This is meant for debugging.
 * @return Pretty representation of this byte tree.
 * @method
 */
ByteTree.prototype.toPrettyString = function () {
    return this.toPrettyStringInner("");
};
