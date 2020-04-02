
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

// ######################################################################
// ################### SigmaProofOr #####################################
// ######################################################################

/**
 * @description Let R be an NP relation for which there is a Sigma
 * proof (P, V), let c > 0 be an integer, and define the NP relation
 * R(c) to consist of all pairs of the form (x, (w, i)) such that
 * (x[i], w) is contained in R for some 0 <= i < c. This class gives a
 * Sigma proof for R(c) provided that:
 *
 * <ol>
 *
 * <li> The challenge space of V is a finite additive group, i.e.,
 *      challenges implement add() and sub() for addition and
 *      subtraction, and toByteTree().
 *
 * <li> The challenge is uniquely determined by the proof commitment
 *      and the reply. It may suffice that it is infeasible to find
 *      two distinct challenges that give accepting transcripts, but
 *      great care is needed.
 *
 * </ol>
 *
 * @param challengeSpace Space of challenges. This must implement a
 * method toElement() that converts a byte tree to a challenge.
 * @param param Array of proofs in which case the second parameter
 * must not be used, or a single sigma proof in which case the second
 * parameter must be a positive integer.
 * @param copies Number of copies in case the first parameter is a
 * single sigma proof.
 * @class
 * @extends verificatum.crypto.SigmaProofPara
 * @memberof verificatum.crypto
 */
function SigmaProofOr(challengeSpace, param, copies) {
    SigmaProofPara.call(this, param);
    this.challengeSpace = challengeSpace;
    this.uniform = typeof copies === "undefined";
}
SigmaProofOr.prototype = Object.create(SigmaProofPara.prototype);
SigmaProofOr.prototype.constructor = SigmaProofOr;

// Internal function.
SigmaProofOr.genSigmaProofs = function (param, copies) {
    if (typeof copies === "undefined") {
        return param;
    } else {
        return util.full(param, copies);
    }
};

// Sum the elements in the array.
SigmaProofOr.sum = function (array) {
    var s = array[0];
    for (var j = 1; j < array.length; j++) {
        s = s.add(array[j]);
    }
    return s;
};

SigmaProofOr.prototype.precomputeRequiresInstance = function() {
    return true;
};

SigmaProofOr.prototype.precomputeWithInstance = function (instances,
                                                          randomSource,
                                                          statDist) {
    // Generate challenges.
    var challenges = [];
    for (var i = 0; i < this.sigmaProofs.length; i++) {
        challenges[i] = this.sigmaProofs[0].challenge(randomSource, statDist);
    }

    // Simulate each sigma proof separately with challenges.
    var pre = SigmaProofPara.prototype.simulate.call(this, instances, challenges,
                                                     randomSource, statDist);
    // View challenges and replies as the replies.
    var precomputed = [pre[0], [challenges, pre[1]]];

    // If the proofs are identical, then we pre-compute a single commitment.
    if (this.uniform) {
        precomputed[2] = this.sigmaProofs[0].precompute(randomSource, statDist);
    }
    return precomputed;
};

SigmaProofOr.prototype.commit = function (precomputed, instance, witness,
                                          randomSource, statDist) {
    var i = witness[1];

    // We compute the commitment if it has not been pre-computed.
    if (!this.uniform) {
        precomputed[2] = this.sigmaProofs[i].precompute(randomSource, statDist);
    }

    // Replace the ith simulated commitment by a real commitment.
    precomputed[0][i] = precomputed[2][1];

    return [precomputed, precomputed[0]];
};

SigmaProofOr.prototype.reply = function (precomputed, witness, challenge) {
    var i = witness[1];

    // Replace the simulated ith challenge such that the challenges
    // sum to the input challenge.
    var sum = SigmaProofOr.sum(precomputed[1][0]);
    sum = sum.sub(precomputed[1][0][i]);
    precomputed[1][0][i] = challenge.sub(sum);

    // Replace the simulated ith reply by computing the reply to the
    // updated ith challenge.
    precomputed[1][1][i] = this.sigmaProofs[i].reply(precomputed[2][0],
                                                     witness[0],
                                                     precomputed[1][0][i]);
    return precomputed[1];
};

SigmaProofOr.prototype.replyToByteTree = function (reply) {
    var cbts = [];
    for (var i = 0; i < this.sigmaProofs.length; i++) {
        cbts[i] = reply[0][i].toByteTree();
    }
    var cbt = new eio.ByteTree(cbts);
    var rbt = SigmaProofPara.prototype.replyToByteTree.call(this, reply[1]);
    return new eio.ByteTree([cbt, rbt]);
};

SigmaProofOr.prototype.byteTreeToReply = function (byteTree) {
    if (!byteTree.isLeaf() && byteTree.value.length === 2) {
        var cbt = byteTree.value[0];
        var rbt = byteTree.value[1];

        var challenge;
        if (!cbt.isLeaf() && cbt.value.length === this.sigmaProofs.length) {
            challenge = [];
            for (var i = 0; i < this.sigmaProofs.length; i++) {
                challenge[i] = this.challengeSpace.toElement(cbt.value[i]);
            }
        } else {
            throw Error("Byte tree has wrong number of children!");
        }
        var reply =
            SigmaProofPara.prototype.byteTreeToReply.call(this, rbt);

        return [challenge, reply];
    } else {
        throw Error("Byte tree has wrong number of children!");
    }
};

SigmaProofOr.prototype.check = function (instance, commitment,
                                         challenge, reply) {

    // Check that the sum of the individual challenges equal the
    // challenge and check each individual proof independently.
    var s = SigmaProofOr.sum(reply[0]);
    return s.equals(challenge) &&
        SigmaProofPara.prototype.check.call(this,
                                            instance, commitment,
                                            reply[0], reply[1]);
};

SigmaProofOr.prototype.simulate = function (instance, challenge,
                                            randomSource, statDist) {
    // Generate random challenges summing to the input challenge.
    var challenges = [];
    for (var i = 0; i < this.sigmaProofs.length - 1; i++) {
        challenges[i] = this.sigmaProofs[0].challenge(randomSource, statDist);
    }
    var sum = SigmaProofOr.sum(challenges);
    challenges[this.sigmaProofs.length - 1] = challenge.sub(sum);

    // Simulate each sigma proof separately with challenges.
    var pre = SigmaProofPara.prototype.simulate.call(this,
                                                     instance, challenges,
                                                     randomSource, statDist);
    // View challenges and replies as the replies.
    return [pre[0], [challenges, pre[1]]];
};
