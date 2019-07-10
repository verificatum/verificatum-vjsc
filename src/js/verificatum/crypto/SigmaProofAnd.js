
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
// ################### SigmaProofAnd ####################################
// ######################################################################

M4_NEEDS(verificatum/crypto/SigmaProofPara.js)dnl

/**
 * @description Conjunction of Sigma proofs with identical challenge
 * spaces.
 *
 * @param sigmaProofs Component Sigma proofs.
 * @class
 * @extends verificatum.crypto.SigmaProofPara
 * @memberof verificatum.crypto
 */
function SigmaProofAnd(sigmaProofs) {
    SigmaProofPara.call(this, sigmaProofs);
}
SigmaProofAnd.prototype = Object.create(SigmaProofPara.prototype);
SigmaProofAnd.prototype.constructor = SigmaProofAnd;

SigmaProofAnd.prototype.randomnessByteLength = function (statDist) {
    var byteLength = 0;
    for (var i = 0; i < this.sigmaProofs.length; i++) {
        byteLength += this.sigmaProofs[i].randomnessByteLength(statDist);
    }
    return byteLength;
};

SigmaProofAnd.prototype.precompute = function (randomSource, statDist) {
    var precomputed = [];

    for (var i = 0; i < this.sigmaProofs.length; i++) {
        precomputed[i] = this.sigmaProofs[i].precompute(randomSource, statDist);
    }
    return precomputed;
};

SigmaProofAnd.prototype.commit = function (precomputed, instance, witness,
                                           randomSource, statDist) {
    var newPrecomputed = [];
    var commitment = [];
    for (var i = 0; i < this.sigmaProofs.length; i++) {
        var pair = this.sigmaProofs[i].commit(precomputed[i],
                                              instance[i], witness[i],
                                              randomSource, statDist);
        newPrecomputed[i] = pair[0];
        commitment[i] = pair[1];
    }
    return [newPrecomputed, commitment];
};

SigmaProofAnd.prototype.check = function (instance, commitment,
                                          challenge, reply) {
    var chall = util.fill(challenge, this.sigmaProofs.length);
    return SigmaProofPara.prototype.check.call(this,
                                               instance, commitment,
                                               chall, reply);
};

SigmaProofAnd.prototype.simulate = function (instance, challenge,
                                             randomSource, statDist) {
    var chall = util.fill(challenge, this.sigmaProofs.length);
    return SigmaProofPara.prototype.simulate.call(this,
                                                  instance, chall,
                                                  randomSource, statDist);
};
