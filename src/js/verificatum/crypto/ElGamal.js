
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
// ################### ElGamal ##########################################
// ######################################################################

M4_NEEDS(verificatum/arithm/PPRing.js)dnl
M4_NEEDS(verificatum/arithm/PPGroup.js)dnl

/**
 * @description The El Gamal cryptosystem implemented on top of {@link
 * verificatum.arithm.PGroup}. This is a generalized implementation in
 * several ways and eliminates the complexity that plagues other
 * implementations by proper abstractions.
 *
 * <p>
 *
 * The first generalization allows us to use multiple El Gamal public
 * keys in parallel. The second allows us to define and implement the
 * Naor-Yung cryptosystem directly from the El Gamal cryptosystem and
 * a proof equal exponents (see {@link
 * verificatum.crypto.ElGamalZKPoK}). The third generalizes the
 * cryptosystem to any width of plaintexts, i.e., lists of plaintexts
 * or equivalently elements of product groups.
 *
 * <ul>
 *
 * <li> The first generalization is captured by letting the underlying
 *      group G be of the form G = H^k, where H is a group of prime
 *      order q and k > 0 is the key width, and the private key is
 *      contained in the ring of exponents R = (Z/qZ)^k of G, where
 *      Z/qZ is the field of prime order q.
 *
 * <li> In the standard cryptosystem the private key is an element x
 *      of R, and the public key has the form (g, y), where g is an
 *      element of G and y = g^x. In the second generalization we
 *      instead allow the public key to be an element ((g, h), y) of
 *      (G x G) x G, but still define y = g^x with x in R. Here h can
 *      be defined as h = y^z for a random z in R.
 *   <p>
 *      The standard cryptosystem defines encryption of a message m in
 *      G as Enc((g, y), m, r) = (g^r, y^r * m), where r is randomly
 *      chosen in R. We generalize encryption by simply setting
 *      Enc(((g, h), y), m, r) = ((g^r, h^r), y^r * m). Note that the
 *      same exponent r is used for all three exponentiations and that
 *      it resides in R.
 *   <p>
 *      The standard cryptosystem defines decryption of a ciphertext
 *      (u, v) by Dec(x, (u, v)) = v / u^x. In the generalized version
 *      a decryption is defined by Dec(x, ((u, a), v)) = v / u^x.
 *
 * <li> We generalize the cryptosystem to allow encryption of
 *      plaintexts m of width w contained in G' = G^w, or equivalently
 *      lists of plaintexts in G. A simple way to accomplish this with
 *      a proper implementation of groups (see {@link
 *      verificatum.arithm.PGroup}) is to simply widen public and
 *      secret keys.
 *
 *      <ol>
 *
 *      <li> The original secret key is replaced by x' = (x, x,..., x)
 *           in R' = R^w.
 *
 *      <li> A public key (g, y) in G x G is replaced by (g', y'),
 *           where y' = (g, g,..., g) and y' = (y, y,..., y) are
 *           elements in G'. Thus, the new public key is contained in
 *           G' x G'.
 *
 *      <li> A public key ((g, h), y) in (G x G) x G is replaced by a
 *           wider public key ((g', h'), y'), where g', and y' are
 *           defined as above and h' is defined accordingly. Thus, the
 *           new public key is contained in (G' x G') x G'.
 *
 *      </ol>
 *
 * </ul>
 *
 * @param standard Determines if the standard or variant El Gamal
 * cryptosystem is used.
 * @param pGroup Group G over which the cryptosystem is defined.
 * @param random Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @class
 * @memberof verificatum.crypto
 */
function ElGamal(standard, pGroup, randomSource, statDist) {
    this.standard = standard;
    this.pGroup = pGroup;
    this.randomSource = randomSource;
    this.statDist = statDist;
};
ElGamal.prototype = Object.create(Object.prototype);
ElGamal.prototype.constructor = ElGamal;

/**
 * @description Computes the number of random bytes needed to encrypt.
 * @return Number of random bytes needed to encrypt.
 * @method
 */
ElGamal.prototype.randomnessByteLength = function (publicKey) {
    publicKey.project(1).pGroup.pRing.randomElementByteLength(this.statDist);
};

/**
 * @description Generates a key pair of the El Gamal cryptosystem.
 * @return Pair [pk, sk] such that pk is a public key in G x G or in
 * (G x G) x G depending on if the standard or variant scheme is used,
 * and sk is the corresponding private key contained in R.
 * @method
 */
ElGamal.prototype.gen = function () {

    var pGroup = this.pGroup;

    // Generate secret key.
    var sk = pGroup.pRing.randomElement(this.randomSource, this.statDist);

    var ghGroup;
    var gh;

    // Standard public key.
    if (this.standard) {
        ghGroup = pGroup;
        gh = pGroup.getg();

        // Variant public key.
    } else {
        var r = pGroup.pRing.randomElement(this.randomSource, this.statDist);
        var h = pGroup.getg().exp(r);

        ghGroup = new verificatum.arithm.PPGroup([pGroup, pGroup]);
        gh = ghGroup.prod([pGroup.getg(), h]);
    }
    var pkGroup = new verificatum.arithm.PPGroup([ghGroup, pGroup]);
    var pk = pkGroup.prod([gh, pGroup.getg().exp(sk)]);

    return [pk, sk];
};

/**
 * @description Pre-computation for encrypting a message using {@link
 * verificatum.crypto.ElGamal.completeEncrypt}.
 * @param publicKey Public key of the form (g', y'), or ((g', h'), y')
 * depending on if the standard or variant scheme is used.
 * @param random Randomness r in R' used for encryption. If this is
 * empty, then it is generated.
 * @return Triple of the form [r, u, v] or [r, (u, a), v], where u =
 * (g')^r, a = (h')^r, and v = (y')^r, depending on if the standard or
 * variant scheme is used.
 * @method
 */
ElGamal.prototype.precomputeEncrypt = function (publicKey, random) {
    var gh = publicKey.project(0);
    var y = publicKey.project(1);

    var r;
    if (typeof random === "undefined") {

        // Note that we choose r in R and not the ring of exponents of
        // the group in which g is contained.
        r = y.pGroup.pRing.randomElement(this.randomSource, this.statDist);
    } else {
        r = random;
    }
    return [r, gh.exp(r), y.exp(r)];
};

/**
 * @description Completes the encryption of a message with the El
 * Gamal cryptosystem.
 * @param publicKey Public key of the form (g', y'), or ((g', h'), y')
 * depending on if the standard or variant scheme is used.
 * @param ruv Triple of the form [r, u, v] or [r, (u, a), v] as output
 * by {@link verificatum.crypto.ElGamal.precomputeEncrypt}, depending on
 * if the standard or variant scheme is used.
 * @param message Message in G' to encrypt (must match group used in
 * pre-computation).
 * @return Ciphertext of the form (u, v * message) or ((u, a), v *
 * message), depending on if the standard or variant scheme is used.
 * @method
 */
ElGamal.prototype.completeEncrypt = function (publicKey, ruv, message) {
    return publicKey.pGroup.prod([ruv[1], ruv[2].mul(message)]);
};

/**
 * @description Encrypts a message with the El Gamal cryptosystem.
 * @param publicKey Public key.
 * @param message Message in G' to encrypt.
 * @param random Randomness r in R' used for decryption. If this is
 * empty, then it is generated.
 * @return Ciphertext of the form output by {@link
 * verificatum.crypto.ElGamal.completeEncrypt}.
 * @method
 */
ElGamal.prototype.encrypt = function (publicKey, message, random) {
    var ruv = this.precomputeEncrypt(publicKey, random);
    return this.completeEncrypt(publicKey, ruv, message);
};

/**
 * @description Decrypts an El Gamal ciphertext.
 * @param privateKey Private key x' contained in R'.
 * @param ciphertext Ciphertext (u, v) in G' x G', or ((u, a), v) in
 * (G' x G') x G') to be decrypted, depending on if the standard or
 * variant scheme is used.
 * @return Plaintext computed as v / u^(x').
 * @method
 */
ElGamal.prototype.decrypt = function (privateKey, ciphertext) {
    var ua = ciphertext.project(0);
    var v = ciphertext.project(1);
    var u;

    // Use ua directly for standard ciphertexts and only first
    // component otherwise.
    if (this.standard) {
        u = ua;
    } else {
        u = ua.project(0);
    }
    return v.mul(u.exp(privateKey.neg()));
};

/**
 * @description Widens a public key such that an element from a
 * product group of the underlying group can be encrypted.
 * @param publicKey Original public key.
 * @param width Width of wider public key.
 * @return Public key with the same key width, but with the given
 * width.
 */
ElGamal.prototype.widePublicKey = function (publicKey, width) {
    if (width > 1) {
        var pkGroup = publicKey.pGroup;

        // Widen second component.
        var yGroup = pkGroup.project(1);
        var y = publicKey.project(1);

        var wyGroup = new verificatum.arithm.PPGroup(yGroup, width);
        var wy = wyGroup.prod(y);

        // Widen first component.
        var ghGroup = pkGroup.project(0);
        var gh = publicKey.project(0);

        var wghGroup;
        var wgh;

        if (ghGroup.equals(yGroup)) {
            wghGroup = wyGroup;
            wgh = wghGroup.prod(gh);
        } else {

            // Extract components
            var g = gh.project(0);
            var h = gh.project(1);

            // Widen each part.
            var wg = wyGroup.prod(g);
            var wh = wyGroup.prod(h);

            // Combine the parts.
            wghGroup = new verificatum.arithm.PPGroup(wyGroup, 2);
            wgh = wghGroup.prod([wg, wh]);
        }

        var wpkGroup = new verificatum.arithm.PPGroup([wghGroup, wyGroup]);
        return wpkGroup.prod([wgh, wy]);

    } else {
        return publicKey;
    }
};

/**
 * @description Widens a private key such that a ciphertext resulting
 * from the encryption with the correspondingly widened public key can
 * be decrypted.
 * @param privateKey Original private key.
 * @param width Width of wider public key.
 * @return Public key with the same key width, but with the given
 * width.
 */
ElGamal.prototype.widePrivateKey = function (privateKey, width) {
    if (width > 1) {
        var wskRing = new verificatum.arithm.PPRing(privateKey.pRing, width);
        return wskRing.prod(privateKey);
    } else {
        return privateKey;
    }
};

/**
 * @description Estimates the running time of encryption in
 * milliseconds.
 * @param standard Indicates if the standard or variant scheme is
 * used.
 * @param pGroup Group over which the cryptosystem is defined.
 * @param width Width of plaintexts.
 * @param minSamples Minimum number of executions performed.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @return Estimated running time of encryption in milliseconds.
 */
ElGamal.benchEncryptPGroupWidth = function (standard, pGroup, width,
                                            minSamples, randomSource, statDist) {
    var eg = new ElGamal(standard, pGroup, randomSource, statDist);

    var keys = eg.gen();
    var wpk = eg.widePublicKey(keys[0], width);
    var m = wpk.pGroup.project(1).getg();

    var start = util.time_ms();
    var j = 0;
    while (j < minSamples) {
        eg.encrypt(wpk, m);
        j++;
    }
    return (util.time_ms() - start) / j;
};

/**
 * @description Estimates the running time of encryption in
 * milliseconds for various widths.
 * @param standard Indicates if the standard or variant scheme is
 * used.
 * @param pGroup Group over which the cryptosystem is defined.
 * @param maxWidth Maximal width of plaintexts.
 * @param minSamples Minimum number of executions performed.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @return Array of estimated running times of encryption in
 * milliseconds.
 */
ElGamal.benchEncryptPGroup = function (standard, pGroup, maxWidth,
                                       minSamples, randomSource, statDist) {
    var results = [];
    for (var i = 1; i <= maxWidth; i++) {
        var t = ElGamal.benchEncryptPGroupWidth(standard, pGroup, i,
                                                minSamples, randomSource,
                                                statDist);
        results.push(t);
    }
    return results;
};

/**
 * @description Estimates the running time of encryption in
 * milliseconds for various groups and widths.
 * @param standard Indicates if the standard or variant scheme is
 * used.
 * @param pGroups Groups over which the cryptosystem is defined.
 * @param maxWidth Maximal width of plaintexts.
 * @param minSamples Minimum number of executions performed.
 * @param randomSource Source of randomness.
 * @param statDist Statistical distance from the uniform distribution
 * assuming that the output of the instance of the random source is
 * perfect.
 * @return Array or arrays of estimated running time of encryption in
 * milliseconds.
 */
ElGamal.benchEncrypt = function (standard, pGroups, maxWidth,
                                 minSamples, randomSource, statDist) {
    var results = [];
    for (var i = 0; i < pGroups.length; i++) {
        results[i] = ElGamal.benchEncryptPGroup(standard, pGroups[i], maxWidth,
                                                minSamples, randomSource,
                                                statDist);
    }
    return results;
};
