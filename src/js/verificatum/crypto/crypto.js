
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
