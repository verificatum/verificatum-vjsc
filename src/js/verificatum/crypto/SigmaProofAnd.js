
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
