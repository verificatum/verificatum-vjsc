
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
// ################### SigmaProof #########################################
// ######################################################################

M4_NEEDS(verificatum/crypto/ZKPoK.js)dnl

/* jshint -W098 */ /* Ignore unused. */
/* eslint-disable no-unused-vars */
/**
 * @description A public-coin three-message special sound and special
 * zero-knowledge protocol, i.e., a Sigma proof, made non-interactive
 * in the random oracle model using the Fiat-Shamir heuristic.
 *
 * <p>
 *
 * Recall that public-coin means that the verifier's challenge message
 * is simply a random bit string and that the verdict is computed from
 * the transcript. Special soundness means that given two accepting
 * transcripts (A, v, k) and (A, v', k') such that v != v' a witness w
 * can be computed such that (x, w) is in the NP relation (this is why
 * it is a proof of knowledge). Special zero-knowledge means that
 * there is an efficient simulator Sim such that for every fixed
 * verifier challenge v: Sim(x, v) is identically distributed to a
 * transcript of an execution on x with the verifier challenge v.
 *
 * <p>
 *
 * The Fiat-Shamir heuristic can be applied, since the protocol is
 * public-coin. We use a systematic approach to generate a proper
 * prefix.
 *
 * @class
 * @abstract
 * @extends verificatum.crypto.ZKPoK
 * @memberof verificatum.crypto
 */
function SigmaProof() {
    ZKPoK.call(this);
}
SigmaProof.prototype = Object.create(ZKPoK.prototype);
SigmaProof.prototype.constructor = SigmaProof;

/* istanbul ignore next */
/**
 * @description Converts an instance to a byte tree.
 * @param instance Instance.
 * @return Byte tree representation of the instance.
 * @method
 */
SigmaProof.prototype.instanceToByteTree = function (instance) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes a pair of updated pre-computed values and a
 * commitment.
 * @param precomputed Pre-computed values.
 * @param instance Instance.
 * @param witness Witness.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Pair of updated pre-computed values and a commitment.
 * @method
 */
SigmaProof.prototype.commit = function (precomputed, instance, witness,
                                        randomSource, statDist) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Converts a commitment to a byte tree.
 * @param commitment Commitment.
 * @return Byte tree representation of the commitment.
 * @method
 */
SigmaProof.prototype.commitmentToByteTree = function (commitment) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Converts a byte tree to a commitment.
 * @param byteTree Byte tree representation of a commitment.
 * @return Commitment.
 * @method
 */
SigmaProof.prototype.byteTreeToCommitment = function (byteTree) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes the challenge of the verifier using either a
 * source of randomness or by applying the Fiat-Shamir heuristic to a
 * byte tree using a given hash function.
 * @param first Source of randomness, or data to be hashed.
 * @param second Statistical distance from the uniform distribution
 * assuming a perfect random source, or a hash function used to
 * implement the Fiat-Shamir heuristic.
 * @return Challenge of the verifier.
 * @method
 */
SigmaProof.prototype.challenge = function (first, second) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes the reply of the prover.
 * @param precomputed Pre-computed values needed to compute the reply.
 * @param witness Witness.
 * @param challenge Challenge of the verifier.
 * @param randomness Randomness used to form the commitment.
 * @return Reply of the prover.
 * @method
 */
SigmaProof.prototype.reply = function (precomputed, witness, challenge) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Converts a reply to a byte tree.
 * @param reply Reply.
 * @return Byte tree representation of the reply.
 * @method
 */
SigmaProof.prototype.replyToByteTree = function (reply) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Converts a byte tree to a reply.
 * @param byteTree Byte tree representation of a reply.
 * @return Reply.
 * @method
 */
SigmaProof.prototype.byteTreeToReply = function (byteTree) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Computes the verdict of the verifier on a transcript.
 * @param instance Instance.
 * @param commitment Commitment.
 * @param challenge Challenge of the prover.
 * @param witness Witness.
 * @param reply Reply.
 * @return Verdict of the verifier as a boolean.
 * @method
 */
SigmaProof.prototype.check = function (instance, commitment, challenge, reply) {
    throw Error("Abstract method!");
};

/* istanbul ignore next */
/**
 * @description Simulates a commitment and reply for the given
 * challenge.
 * @param instance Instance.
 * @param challenge Challenge of the verifier.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming a perfect random source.
 * @return Pair of a commitment and reply.
 * @method
 */
SigmaProof.prototype.simulate = function (instance, challenge,
                                          randomSource, statDist) {
    throw Error("Abstract method!");
};

/* jshint +W098 */ /* Stop ignoring unused. */
/* eslint-enable no-unused-vars */

SigmaProof.prototype.completeProof = function (precomputed,
                                               label, instance, witness,
                                               hashfunction,
                                               randomSource, statDist) {
    var pair =
        this.commit(precomputed, instance, witness, randomSource, statDist);
    precomputed = pair[0];
    var commitment = pair[1];

    // We must wrap byte array labels to get an invertible complete
    // prefix. Then we simply pack label, instance, and commitment.
    var lbt = eio.ByteTree.asByteTree(label);
    var ibt = this.instanceToByteTree(instance);
    var cbt = this.commitmentToByteTree(commitment);
    var bt = new eio.ByteTree([lbt, ibt, cbt]);

    var challenge = this.challenge(bt, hashfunction);

    var reply = this.reply(precomputed, witness, challenge);

    var rbt = this.replyToByteTree(reply);
    var pbt = new eio.ByteTree([cbt, rbt]);
    return pbt.toByteArray();
};

SigmaProof.prototype.verify = function (label, instance, hashfunction, proof) {
    try {
        var pbt = eio.ByteTree.readByteTreeFromByteArray(proof);
        if (!pbt.isLeaf() && pbt.value.length === 2) {

            // We must wrap byte array labels to get an invertible
            // complete prefix.
            var lbt = eio.ByteTree.asByteTree(label);
            var ibt = this.instanceToByteTree(instance);

            var cbt = pbt.value[0];
            var commitment = this.byteTreeToCommitment(cbt);

            // Then we simply pack label, instance, and commitment.
            var bt = new eio.ByteTree([lbt, ibt, cbt]);
            var challenge = this.challenge(bt, hashfunction);

            var rbt = pbt.value[1];
            var reply = this.byteTreeToReply(rbt);

            return this.check(instance, commitment, challenge, reply);
        } else {
            return false;
        }
    } catch (err) {
        return false;
    }
};
