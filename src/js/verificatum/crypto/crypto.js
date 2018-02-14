
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
// ################### crypto ###########################################
// ######################################################################

/**
 * @description Cryptographic objects and algorithms.
 *
 * @namespace crypto
 * @memberof verificatum
 */
var crypto = (function () {

var getStatDist = function (statDist) {
    if (typeof statDist === "undefined") {
        return 50;
    } else {
        return statDist;
    }
};

dnl SHA2.
M4_INCLUDE(verificatum/crypto/sha2.js)dnl

dnl Abstract random source.
M4_INCLUDE(verificatum/crypto/RandomSource.js)dnl

dnl Implementation of random device.
M4_INCLUDE(verificatum/crypto/RandomDevice.js)dnl

dnl Implementation of PRG using SHA-256.
M4_INCLUDE(verificatum/crypto/SHA256PRG.js)dnl

dnl Zero-knowledge proofs of knowledge.
M4_INCLUDEOPT(verificatum/crypto/ZKPoK.js)dnl

dnl Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/SigmaProof.js)dnl

dnl Parallel execution of Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/SigmaProofPara.js)dnl

dnl Conjunction of Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/SigmaProofAnd.js)dnl

dnl Disjunction of Sigma proofs.
M4_INCLUDEOPT(verificatum/crypto/SigmaProofOr.js)dnl

dnl Schnorr proofs.
M4_INCLUDEOPT(verificatum/crypto/SchnorrProof.js)dnl

dnl El Gamal cryptosystem.
M4_INCLUDEOPT(verificatum/crypto/ElGamal.js)dnl

dnl Adapter for El Gamal cryptosystem with zero-knowledge proofs
dnl of knowledge.
M4_INCLUDEOPT(verificatum/crypto/ElGamalZKPoKAdapter.js)dnl

dnl El Gamal cryptosystem with zero-knowledge proofs of knowledge.
M4_INCLUDEOPT(verificatum/crypto/ElGamalZKPoK.js)dnl

dnl Proof of knowledge of plaintext for the El Gamal cryptosystem.
M4_INCLUDEOPT(verificatum/crypto/ZKPoKWriteIn.js)dnl

dnl Adapter for proof of knowledge of plaintext for the El Gamal cryptosystem.
M4_INCLUDEOPT(verificatum/crypto/ZKPoKWriteInAdapter.js)dnl

dnl El Gamal cryptosystem with zero-knowledge proof for write-in votes.
M4_INCLUDEOPT(verificatum/crypto/ElGamalZKPoKWriteIn.js)dnl

    return {
        "sha256": sha256,
        "getStatDist": getStatDist,
        "RandomSource": RandomSource,
        "RandomDevice": RandomDevice,
        "SHA256PRG": SHA256PRG,
M4_EXPOPT(verificatum/crypto/SigmaProof.js,SigmaProof)
M4_EXPOPT(verificatum/crypto/SigmaProofPara.js,SigmaProofPara)
M4_EXPOPT(verificatum/crypto/SigmaProofAnd.js,SigmaProofAnd)
M4_EXPOPT(verificatum/crypto/SigmaProofOr.js,SigmaProofOr)
M4_EXPOPT(verificatum/crypto/SchnorrProof.js,SchnorrProof)
M4_EXPOPT(verificatum/crypto/ElGamal.js,ElGamal)
M4_EXPOPT(verificatum/crypto/ElGamalZKPoKAdapter.js,ElGamalZKPoKAdapter)
M4_EXPOPT(verificatum/crypto/ElGamalZKPoK.js,ElGamalZKPoK)
M4_EXPOPT(verificatum/crypto/ZKPoKWriteIn.js,ZKPoKWriteIn)
M4_EXPOPT(verificatum/crypto/ZKPoKWriteInAdapter.js,ZKPoKWriteInAdapter)
M4_EXPOPT(verificatum/crypto/ElGamalZKPoKWriteIn.js,ElGamalZKPoKWriteIn)
    };
})();
