
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

M4_NEEDS(verificatum/arithm/ec.js)dnl
M4_NEEDS(verificatum/arithm/PField.js)dnl
M4_NEEDS(verificatum/arithm/PGroup.js)dnl
M4_NEEDS(verificatum/arithm/ECqPGroup_named_curves.js)dnl

// ######################################################################
// ################### ECqPGroupElement #################################
// ######################################################################

/**
 * @description Element of {@link verificatum.arithm.ECqPGroup}.
 * @param pGroup Group to which this point belongs.
 * @param x x-coordinate of point on the curve or an existing instance
 * of {@link verificatum.arithm.ec.ECP}.
 * @param y y-coordinate of point on the curve or empty.
 * @param z z-coordinate of point on the curve or empty (can be empty
 * even if x and y are affine coordinate).
 * @class
 * @extends verificatum.arithm.PGroupElement
 * @memberof verificatum.arithm
 */
function ECqPGroupElement(pGroup, x, y, z) {
    PGroupElement.call(this, pGroup);

    // Input given as an instance of ec.ECP.
    if (typeof y === "undefined") {
        this.value = x;

        // Input is a list of explicit coordinates.
    } else {
        if (typeof z === "undefined") {
            z = LargeInteger.ONE;
        }
        this.value = new ec.ECP(pGroup.curve.length, x, y, z);
    }
};
ECqPGroupElement.prototype = Object.create(PGroupElement.prototype);
ECqPGroupElement.prototype.constructor = ECqPGroupElement;

ECqPGroupElement.prototype.equals = function (other) {
    return this.pGroup.curve.equals(this.value, other.value);
};

ECqPGroupElement.prototype.mul = function (factor) {
    var A = new ec.ECP(this.pGroup.curve.length);
    var B = this.value;
    var C = factor.value;

    this.pGroup.curve.jadd(A, B, C);

    return new ECqPGroupElement(this.pGroup, A);
};

ECqPGroupElement.prototype.square = function () {
    var A = new ec.ECP(this.pGroup.curve.length);
    var B = this.value;

    this.pGroup.curve.jdbl(A, B);

    return new ECqPGroupElement(this.pGroup, A);
};

ECqPGroupElement.prototype.exp = function (exponent) {
    this.expCounter++;

    var A = new ec.ECP(this.pGroup.curve.length);
    var B = this.value;

    if (exponent.constructor === PFieldElement) {
        exponent = exponent.value;
    }
    this.pGroup.curve.jmul(A, B, exponent);

    return new ECqPGroupElement(this.pGroup, A);
};

ECqPGroupElement.prototype.inv = function () {
    var A = new ec.ECP(this.pGroup.curve.length);
    var B = this.value;

    this.pGroup.curve.neg(A, B);

    return new ECqPGroupElement(this.pGroup, A);
};

ECqPGroupElement.prototype.toByteTree = function () {
    var len = this.pGroup.modulusByteLength;

    this.pGroup.curve.affine(this.value);
    if (sli.iszero(this.value.z)) {

        // This is a safe internal representation of the unit element,
        // since there are no usable Mersenne primes within the range
        // of usable moduli.
        var FF = verificatum.util.full(0xFF, len);
        return new verificatum.eio.ByteTree([new verificatum.eio.ByteTree(FF),
                                             new verificatum.eio.ByteTree(FF)]);
    } else {
        var x = new LargeInteger(this.value.x.sign, this.value.x.value);
        var y = new LargeInteger(this.value.y.sign, this.value.y.value);
        var xbt = new verificatum.eio.ByteTree(x.toByteArray(len));
        var ybt = new verificatum.eio.ByteTree(y.toByteArray(len));
        return new verificatum.eio.ByteTree([xbt, ybt]);
    }
};

ECqPGroupElement.prototype.toString = function () {

    this.pGroup.curve.affine(this.value);
    if (sli.iszero(this.value.z)) {
        return "(O)";
    } else {
        var xs = sli.hex(this.value.x);
        var ys = sli.hex(this.value.y);
        return "(" + xs + "," + ys + ")";
    }
};

ECqPGroupElement.prototype.decode = function (destination, startIndex) {

    this.pGroup.curve.affine(this.value);

    // We encode nothing in the point at infinity.
    if (sli.iszero(this.value.z)) {
        return 0;
    } else {

        // Strip the last byte, read the length, and copy bytes.
        var x = new LargeInteger(this.value.x.sign, this.value.x.value);
        var elen = this.pGroup.encodeLength;
        var xbytes = x.toByteArray(elen + 3);
        var len = verificatum.util.readUint16FromByteArray(xbytes, elen);
        var i = startIndex;
        var j = this.pGroup.encodeLength - len;
        while (j < this.pGroup.encodeLength) {
            destination[i] = xbytes[j];
            i++;
            j++;
        }
        return len;
    }
};


// ######################################################################
// ################### ECqPGroup ########################################
// ######################################################################

/**
 * @description Elliptic curve group over prime order fields.
 *
 * <p>
 *
 * ASSUMES: 0 <= a, b, gx, gy < modulus, n > 0 and that x^3 + b * x +
 * a (mod modulus) is a non-singular curve of order n.
 *
 * @param modulus Modulus for underlying field, or the name of a
 * standard curve, in which case the remaining parameters must be
 * empty.
 * @param a First coefficient for curve of Weierstrass normal form.
 * @param b Second coefficientfor curve of Weierstrass normal form.
 * @param gx x-coefficient of standard generator.
 * @param gy y-coefficient of standard generator.
 * @param n Order of elliptic curve.
 * @class
 * @extends verificatum.arithm.PGroup
 * @memberof verificatum.arithm
 */
function ECqPGroup(modulus, a, b, gx, gy, n) {
    PGroup.call(this, ECqPGroup.genPField(modulus, n));

    if (typeof a === "undefined") {
        var params = ECqPGroup.getParams(modulus);
        modulus = new LargeInteger(params[0]);
        a = new LargeInteger(params[1]);
        b = new LargeInteger(params[2]);
        gx = new LargeInteger(params[3]);
        gy = new LargeInteger(params[4]);
        n = new LargeInteger(params[5]);
    }
    this.curve = new verificatum.arithm.ec.EC(modulus, a, b);
    this.generator = new ECqPGroupElement(this, gx, gy);
    this.ONE = new ECqPGroupElement(this,
                                    LargeInteger.ZERO,
                                    LargeInteger.ONE,
                                    LargeInteger.ZERO);

    this.modulusByteLength = modulus.toByteArray().length;

    // Strip most significant bit and keep two bytes for size and one
    // for padding.
    this.encodeLength = Math.floor((modulus.bitLength() - 1) / 8) - 3;
};
ECqPGroup.prototype = Object.create(PGroup.prototype);
ECqPGroup.prototype.constructor = ECqPGroup;

ECqPGroup.prototype.getEncodeLength = function () {
    return this.encodeLength;
};

ECqPGroup.prototype.equals = function (other) {
    if (this === other) {
        return true;
    }
    if (other.getName() !== "ECqPGroup") {
        return false;
    }

    return this.curve.modulus.equals(other.curve.modulus) &&
        this.curve.a.equals(other.curve.a) &&
        this.curve.b.equals(other.curve.b) &&
        this.getg().equals(other.getg());
};

ECqPGroup.genPField = function (curveName, n) {
    if (typeof n === "undefined") {
        var params = ECqPGroup.getParams(curveName);
        return new PField(new LargeInteger(params[5]));
    } else {
        return new PField(n);
    }
};

ECqPGroup.getParams = function (curveName) {
    var params = ECqPGroup.named_curves[curveName];
    if (typeof params === "undefined") {
        throw Error("Unknown curve name! (" + curveName + ")");
    } else {
        return params;
    }
};

/**
 * @description Returns an array of all available curve names.
 * @return Array of all available curve names.
 * @function getPGroupNames
 * @memberof verificatum.arithm.ECqPGroup
 */
ECqPGroup.getPGroupNames = function () {
    return Object.keys(ECqPGroup.named_curves);
};

/**
 * @description Returns the group with the given name.
 * @return Named group.
 * @function getPGroup
 * @memberof verificatum.arithm.ECqPGroup
 */
ECqPGroup.getPGroup = function (groupName) {
    var params = ECqPGroup.named_curves[groupName];
    if (typeof params === "undefined") {
        return null;
    } else {
        return new ECqPGroup(groupName);
    }
};

/**
 * @description Returns an array of all available curves.
 * @return Array of all available curves.
 * @function getPGroups
 * @memberof verificatum.arithm.ECqPGroup
 */
ECqPGroup.getPGroups = function () {
    var pGroupNames = ECqPGroup.getPGroupNames();
    var pGroups = [];
    for (var i = 0; i < pGroupNames.length; i++) {
        pGroups[i] = new ECqPGroup(pGroupNames[i]);
    }
    return pGroups;
};

dnl Table of parameters of named standard curves.
    M4_INCLUDE(verificatum/arithm/ECqPGroup_named_curves.js)dnl

/**
 * @description Recovers a ECqPGroup instance from its representation
 * as a byte tree.
 * @param byteTree Byte tree representation of a ECqPGroup instance.
 * @return Instance of ECqPGroup.
 * @function fromByteTree
 * @memberof verificatum.arithm.ECqPGroup
 */
ECqPGroup.fromByteTree = function (byteTree) {
    if (!byteTree.isLeaf()) {
        throw Error("Byte tree is not a leaf!");
    }
    var curveName = verificatum.util.byteArrayToAscii(byteTree.value);
    return new ECqPGroup(curveName);
};

ECqPGroup.prototype.getPrimeOrderPGroup = function () {
    return this;
};

/**
 * @description Evaluates f(x) = x^3 + a * x + b.
 * @param x x-coordinate of point on the curve.
 * @return Value of f at x.
 * @method
 */
ECqPGroup.prototype.f = function (x) {
    var p = this.curve.modulus;
    var x3 = x.mul(x).mod(p).mul(x).mod(p);
    var ax = this.curve.a.mul(x).mod(p);
    return x3.add(ax).add(this.curve.b).mod(p);
};

/**
 * @description Checks if an affine point (x, y) is a point on the
 * curve.
 * @param x x-coordinate of prospective point.
 * @param y y-coordinate of prospective point.
 * @return True or false depending on if (x, y) is on the curve or not.
 * @method
 */
ECqPGroup.prototype.isOnCurve = function (x, y) {
    var fx = this.f(x);
    var y2 = y.mul(y).mod(this.curve.modulus);
    return fx.equals(y2);
};

ECqPGroup.prototype.getElementOrder = function () {
    return this.pRing.order;
};

ECqPGroup.prototype.getg = function () {
    return this.generator;
};

ECqPGroup.prototype.getONE = function () {
    return this.ONE;
};

ECqPGroup.prototype.toElement = function (byteTree) {
    if (byteTree.isLeaf()) {
        throw Error("Byte tree is a leaf, expected a node!");
    } else if (byteTree.value.length !== 2 ||
               !byteTree.value[0].isLeaf() ||
               !byteTree.value[1].isLeaf()) {
        throw Error("Byte tree does not have 2 leaves!");
    } else {
        var xa = byteTree.value[0].value;
        var ya = byteTree.value[1].value;

        if (xa.length !== this.modulusByteLength ||
            ya.length !== this.modulusByteLength) {
            throw Error("A coordinate array has the wrong length!");
        } else {
            for (var i = 0; i < xa.length; i++) {
                if (xa[i] !== 0xFF || ya[i] !== 0xFF) {
                    var x = new LargeInteger(xa);
                    var y = new LargeInteger(ya);
                    return new ECqPGroupElement(this, x, y);
                }
            }

            // Point at infinity is represented by (-1, -1) in "affine
            // coordinates" and we end up here.
            return new ECqPGroupElement(this,
                                        LargeInteger.ZERO,
                                        LargeInteger.ONE,
                                        LargeInteger.ZERO);
        }
    }
};

ECqPGroup.prototype.encode = function (bytes, startIndex, length) {
    var fx;

    if (typeof startIndex === "undefined") {
        startIndex = 0;
        length = bytes.length;
    }

    if (length > this.encodeLength) {
        throw Error("Too many bytes to encode! (" +
                    length + " > " + this.encodeLength + ")");
    } else {
        var bytesToUse = [];
        bytesToUse.length = this.encodeLength + 3;

        var i = 0;
        while (i < this.encodeLength - length) {
            bytesToUse[i] = 0;
            i++;
        }
        var j = startIndex;
        while (i < this.encodeLength) {
            bytesToUse[i] = bytes[j];
            i++;
            j++;
        }
        while (i < bytesToUse.length - 3) {
            bytesToUse[i] = 0;
            i++;
        }
        verificatum.util.setUint16ToByteArray(bytesToUse, length,
                                              this.encodeLength);

        var x = new LargeInteger(bytesToUse);
        var square = false;
        while (!square) {
            fx = this.f(x);
            if (fx.legendre(this.curve.modulus) === 1) {
                square = true;
            } else {
                x = x.add(LargeInteger.ONE);
            }
        }

        var y = fx.modSqrt(this.curve.modulus);

        // Choose smallest root integer representative.
        var yneg = this.curve.modulus.sub(y);
        if (yneg.cmp(y) < 0) {
            y = yneg;
        }
        return new ECqPGroupElement(this, x, y);
    }
};

ECqPGroup.prototype.randomElement = function (randomSource, statDist) {
    var p = new LargeInteger(this.curve.modulus.sign, this.curve.modulus.value);
    var bitLength = p.bitLength() + statDist;

    var x;
    var fx;
    var square = false;
    while (!square) {

        // Generate random element modulo this.curve.modulus.
        x = new LargeInteger(bitLength, randomSource);
        x = x.mod(p);

        // Check if f(x) is a quadratic residue.
        fx = this.f(x);

        if (fx.legendre(p) === 1) {
            square = true;
        }
    }

    // Compute root of square.
    var y = fx.modSqrt(p);

    // Choose smallest root integer representative.
    var yneg = p.sub(y);
    if (yneg.cmp(y) < 0) {
        y = yneg;
    }
    return new ECqPGroupElement(this, x, y);
};

ECqPGroup.prototype.toString = function () {
    return this.curve.modulus.toHexString() + ":" +
        this.getElementOrder().toHexString() + ":" +
        this.generator.toString();
};
