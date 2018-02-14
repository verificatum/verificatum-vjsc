
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
