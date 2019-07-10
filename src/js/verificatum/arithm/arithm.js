
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
// ################### arithm ###########################################
// ######################################################################

/**
 * @description Arithmetic objects and routines. This is a port of the
 * Verificatum Mix-Net (VMN) which introduces abstractions that
 * facilitates the implementation of generalized cryptographic
 * primitives and protocols.
 *
 * <p>
 *
 * More precisely, the implementations of generalized primitives and
 * protocols is syntactically identical to their original versions,
 * e.g., the complex code found in other libraries for handling lists
 * of ciphertexts is completely eliminated. This gives less error
 * prone code, a smaller code base, and the code is easier to verify.
 *
 * @namespace arithm
 * @memberof verificatum
 */
var arithm = (function () {

dnl Root abstract class of arithmetic objects.
M4_INCLUDE(verificatum/arithm/ArithmObject.js)dnl

dnl Basic functionality for large integer arithmetic.
M4_INCLUDE(verificatum/arithm/li.js)dnl

dnl Basic functionality for large signed integer arithmetic.
M4_INCLUDE(verificatum/arithm/sli.js)dnl

dnl Large integer arithmetic.
M4_INCLUDE(verificatum/arithm/LargeInteger.js)dnl

dnl Simultaneous modular exponentiation.
M4_INCLUDEOPT(verificatum/arithm/ModPowProd.js)dnl

dnl Fixed-basis modular exponentiation.
M4_INCLUDEOPT(verificatum/arithm/FixModPow.js)dnl

dnl Prime order fields and product rings.
M4_INCLUDEOPT(verificatum/arithm/PRing.js)dnl

dnl Product ring.
M4_INCLUDEOPT(verificatum/arithm/PPRing.js)dnl

dnl Prime order field.
M4_INCLUDEOPT(verificatum/arithm/PField.js)dnl

dnl Basic elliptic curve arithmetic.
M4_INCLUDEOPT(verificatum/arithm/ec.js)dnl

dnl Abstract group where each non-trivial element has a given prime order.
M4_INCLUDEOPT(verificatum/arithm/PGroup.js)dnl

dnl Prime order subgroups of multiplicative groups modulo primes.
M4_INCLUDEOPT(verificatum/arithm/ModPGroup.js)dnl

dnl Elliptic curve groups over prime order fields.
M4_INCLUDEOPT(verificatum/arithm/ECqPGroup.js)dnl

dnl Product group.
M4_INCLUDEOPT(verificatum/arithm/PPGroup.js)dnl

dnl Homomorphism from ring to group.
M4_INCLUDEOPT(verificatum/arithm/Hom.js)dnl

dnl Exponentiation homomorphism from ring to group.
M4_INCLUDEOPT(verificatum/arithm/ExpHom.js)dnl

    // We only expose top-level objects. All elements of rings and
    // groups are instantiated through their container ring/group to
    // increase robustness.
    return {
        "li": li,
        "sli": sli,
        "LargeInteger": LargeInteger,
M4_EXPOPT(verificatum/arithm/ModPowProd.js,ModPowProd)
M4_EXPOPT(verificatum/arithm/FixModPow.js,FixModPow)
M4_EXPOPT(verificatum/arithm/PRing.js,PRing)
M4_EXPOPT(verificatum/arithm/PField.js,PField)
M4_EXPOPT(verificatum/arithm/PPRing.js,PPRing)
M4_EXPOPT(verificatum/arithm/PGroup.js,PGroup)
M4_EXPOPT(verificatum/arithm/ModPGroup.js,ModPGroup)
M4_EXPOPT(verificatum/arithm/ec.js,ec)
M4_EXPOPT(verificatum/arithm/ECqPGroup.js,ECqPGroup)
M4_EXPOPT(verificatum/arithm/PPGroup.js,PPGroup)
M4_EXPOPT(verificatum/arithm/Hom.js,Hom)
M4_EXPOPT(verificatum/arithm/ExpHom.js,ExpHom)

    };
})();
