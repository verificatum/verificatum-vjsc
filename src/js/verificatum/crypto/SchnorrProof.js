
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
// ################### SchnorrProof #####################################
// ######################################################################

M4_NEEDS(verificatum/arithm/ExpHom.js)dnl
M4_NEEDS(verificatum/crypto/SigmaProof.js)dnl

/**
 * @description Sigma proof of a pre-image of a homomorphism from a
 * ring to a group using a generalized Schnorr proof. More precisely,
 * if Hom : R -> G is a homomorphism, where R is a product ring of a
 * finite field Z/qZ of order q, and every non-trivial element in G
 * has order q, then the protocol is defined as follows on common
 * input x and private input w such that (x, w) is in the NP relation.
 *
 * <ol>
 *
 * <li> Prover chooses a in R randomly and computes A = Hom(a).
 *
 * <li> Verifier chooses a random challenge v in Z/qZ.
 *
 * <li> Prover computes a reply k = w * v + a in R.
 *
 * <li> Verifier accepts if and only if x^v * A = Hom(k), where the
 *      product is taken in G.
 *
 * </ol>
 *
 * @param homomorphism Underlying homomorphism.
 * @class
 * @extends verificatum.crypto.SigmaProof
 * @memberof verificatum.crypto
 */
function SchnorrProof(homomorphism) {
    SigmaProof.call(this);
    this.homomorphism = homomorphism;
}
SchnorrProof.prototype = Object.create(SigmaProof.prototype);
SchnorrProof.prototype.constructor = SchnorrProof;

SchnorrProof.prototype.randomnessByteLength = function (statDist) {
    return this.homomorphism.domain.randomElementByteLength(statDist);
};

SchnorrProof.prototype.instanceToByteTree = function (instance) {
    return instance.toByteTree();
};

SchnorrProof.prototype.precompute = function (randomSource, statDist) {
    // A = Hom(a) for random a.
    var a = this.homomorphism.domain.randomElement(randomSource, statDist);
    var A = this.homomorphism.eva(a);
    return [a, A];
};

SchnorrProof.prototype.commit = function (precomputed) {
    // unused parameters: instance, witness, randomSource, statDist) {
    return precomputed;
};

SchnorrProof.prototype.commitmentToByteTree = function (commitment) {
    return commitment.toByteTree();
};

SchnorrProof.prototype.byteTreeToCommitment = function (byteTree) {
    return this.homomorphism.range.toElement(byteTree);
};

SchnorrProof.prototype.challenge = function (first, second) {
    if (util.ofType(first, eio.ByteTree)) {
        var digest = second.hash(first.toByteArray());
        return this.homomorphism.domain.getPField().toElement(digest);
    } else {
        return this.homomorphism.domain.randomElement(first, second);
    }
};

SchnorrProof.prototype.reply = function (precomputed, witness, challenge) {
    // k = w * v + a
    return witness.mul(challenge).add(precomputed);
};

SchnorrProof.prototype.replyToByteTree = function (reply) {
    return reply.toByteTree();
};

SchnorrProof.prototype.byteTreeToReply = function (byteTree) {
    return this.homomorphism.domain.toElement(byteTree);
};

SchnorrProof.prototype.check = function (instance, commitment,
                                         challenge, reply) {
    // Check if x^v * A = Hom(k).
    var ls = instance.exp(challenge).mul(commitment);
    var rs = this.homomorphism.eva(reply);
    return ls.equals(rs);
};

SchnorrProof.prototype.simulate = function (instance, challenge,
                                            randomSource, statDist) {
    // A = Hom(k) / x^v, for a randomly chosen random k.
    var k = this.homomorphism.domain.randomElement(randomSource, statDist);
    var A = this.homomorphism.eva(k).mul(instance.exp(challenge).inv());
    return [A, k];
};
