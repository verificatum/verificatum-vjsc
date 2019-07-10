
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
// ################### ZKPoKWriteIn #####################################
// ######################################################################

M4_NEEDS(verificatum/crypto/ElGamalZKPoKAdapter.js)dnl
M4_NEEDS(verificatum/arithm/ExpHom.js)dnl
M4_NEEDS(verificatum/crypto/SchnorrProof.js)dnl

/**
 * @description Zero-knowledge proof needed to implement the Naor-Yung
 * cryptosystem.
 * @class
 * @extends verificatum.arithm.ZKPoK
 * @memberof verificatum.crypto
 */
function ZKPoKWriteIn(publicKey) {
    var domain = publicKey.project(1).pGroup.pRing;
    var basis = publicKey.project(0);
    var expHom = new arithm.ExpHom(domain, basis);
    this.sp = new SchnorrProof(expHom);
};
ZKPoKWriteIn.prototype = Object.create(ZKPoK.prototype);
ZKPoKWriteIn.prototype.constructor = ZKPoKWriteIn;

ZKPoKWriteIn.prototype.precompute = function (randomSource, statDist) {
    return this.sp.precompute(randomSource, statDist);
};

/**
 * @description Combines an arbitrary label with parts of the instance
 * not included as input by the ZKPoK itself.
 * @param label Label in the form of a byte array or byte tree.
 * @param instance Complete instance.
 * @return Combined label.
 */
ZKPoKWriteIn.makeLabel = function (label, instance) {
    var lbt = eio.ByteTree.asByteTree(label);
    var ebt = instance.project(1).toByteTree();
    return new eio.ByteTree([lbt, ebt]);
};

ZKPoKWriteIn.prototype.completeProof = function (precomputed,
                                            label, instance, witness,
                                            hashfunction,
                                            randomSource, statDist) {
    label = ZKPoKWriteIn.makeLabel(label, instance);
    return this.sp.completeProof(precomputed, label,
                                 instance.project(0), witness,
                                 hashfunction, randomSource, statDist);
};

ZKPoKWriteIn.prototype.verify = function (label, instance, hashfunction, proof) {
    label = ZKPoKWriteIn.makeLabel(label, instance);
    return this.sp.verify(label, instance.project(0), hashfunction, proof);
};
