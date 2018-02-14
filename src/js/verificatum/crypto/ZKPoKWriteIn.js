
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
