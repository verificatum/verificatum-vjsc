dnl
dnl GENERATED CODE BELOW! DO NOT EDIT! See Makefile.
dnl
dnl Copyright 2008-2018 Douglas Wikstrom
dnl
dnl This file is part of Verificatum JavaScript Cryptographic library
dnl (VJSC).
dnl
dnl VJSC is free software: you can redistribute it and/or modify it
dnl under the terms of the GNU Affero General Public License as
dnl published by the Free Software Foundation, either version 3 of the
dnl License, or (at your option) any later version.
dnl
dnl VJSC is distributed in the hope that it will be useful, but WITHOUT
dnl ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
dnl or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
dnl Public License for more details.
dnl
dnl You should have received a copy of the GNU Affero General Public
dnl License along with VJSC. If not, see <http://www.gnu.org/licenses/>.
dnl
changequote([[[[[,]]]]])dnl
dnl
dnl We only use this for pre-processing dependencies, so it is ignored by M4.
dnl
define([[[[[M4_NEEDS]]]]])dnl
dnl
dnl Enables a file for inclusion. If this is not used, then M4_INCLUDE
dnl has no effect for the given file. Thus, this gives a way to make
dnl custom builds.
dnl
define([[[[[M4_ENABLE]]]]],[[[[[dnl
    define([[[[[M4_ENABLED_$1]]]]])dnl
]]]]])dnl
dnl
dnl We use M4 diversion to conditionally ignore includes. The idea is
dnl basically to decrease the diversion counter when encountering a file
dnl that has already been included and increase it at the end of the
dnl include.
dnl
define([[[[[M4_DIVERSION]]]]],0)dnl
dnl
dnl Used to implement M4_INCLUDE.
dnl
define([[[[[M4_BEGIN_INCLUDE]]]]],[[[[[dnl
    ifdef([[[[[M4_BEGIN_INCLUDE_GUARD_$1]]]]],[[[[[dnl
        define([[[[[M4_DIVERSION]]]]],decr(M4_DIVERSION))dnl
    ]]]]],[[[[[dnl
        define([[[[[M4_BEGIN_INCLUDE_GUARD_$1]]]]])dnl
        define([[[[[M4_INCLUDED_$1]]]]])dnl
    ]]]]])dnl
]]]]])dnl
dnl
dnl Used to implement M4_INCLUDE.
dnl
define([[[[[M4_END_INCLUDE]]]]],[[[[[dnl
    ifdef([[[[[M4_END_INCLUDE_GUARD_$1]]]]],[[[[[dnl
        define([[[[[M4_DIVERSION]]]]],incr(M4_DIVERSION))dnl
    ]]]]],[[[[[dnl
        define([[[[[M4_END_INCLUDE_GUARD_$1]]]]])dnl
    ]]]]])dnl
]]]]])dnl
dnl
dnl Includes the first parameter/file if it was not included previously,
dnl and defines the M4_INCLUDED_<firstparameter> macro. This allows
dnl later checking if the first parameter/file was included.
dnl
define([[[[[M4_INCLUDEOPT]]]]],[[[[[dnl
    ifdef([[[[[M4_ENABLED_$1]]]]],[[[[[dnl
        M4_BEGIN_INCLUDE($1)dnl
        divert(M4_DIVERSION)dnl
        include(M4_JSSRC/$1)dnl
        M4_END_INCLUDE($1)dnl
        divert(M4_DIVERSION)dnl
    ]]]]])dnl
]]]]])dnl
dnl
dnl Always include, does not need to be enabled.
dnl
define([[[[[M4_INCLUDE]]]]],[[[[[dnl
    M4_ENABLE($1)dnl
    M4_INCLUDEOPT($1)dnl
]]]]])dnl
dnl
dnl Generate an export snippet to be used in a namespace if the given
dnl file was included.
dnl
define([[[[[M4_EXPOPT]]]]],[[[[[dnl
    ifdef([[[[[M4_INCLUDED_$1]]]]],[[[[["$2": $2,]]]]])dnl
]]]]])dnl
dnl
dnl Generate a snippet for invoking a test to be used in a namespace
dnl if the given file was included.
dnl
define([[[[[M4_RUNOPT]]]]],[[[[[dnl
    ifdef([[[[[M4_INCLUDED_$1]]]]],[[[[[$2.run($3);]]]]])dnl
]]]]])dnl
dnl
define([[[[[M4_IFN_INCLUDED]]]]],[[[[[dnl
    ifdef([[[[[M4_INCLUDED_$1]]]]],[[[[[dnl
        define([[[[[M4_DIVERSION]]]]],decr(M4_DIVERSION))dnl
        divert(M4_DIVERSION)dnl
    ]]]]])dnl
]]]]])dnl
dnl
define([[[[[M4_FIN_INCLUDED]]]]],[[[[[dnl
    ifdef([[[[[M4_INCLUDED_$1]]]]],[[[[[dnl
        define([[[[[M4_DIVERSION]]]]],incr(M4_DIVERSION))dnl
        divert(M4_DIVERSION)dnl
    ]]]]])dnl
]]]]])dnl
dnl
define([[[[[M4_IF_INCLUDED]]]]],[[[[[dnl
    ifdef([[[[[M4_INCLUDED_$1]]]]],,[[[[[dnl
        define([[[[[M4_DIVERSION]]]]],decr(M4_DIVERSION))dnl
        divert(M4_DIVERSION)dnl
    ]]]]])dnl
]]]]])dnl
dnl
define([[[[[M4_FI_INCLUDED]]]]],[[[[[dnl
    ifdef([[[[[M4_INCLUDED_$1]]]]],,[[[[[dnl
        define([[[[[M4_DIVERSION]]]]],incr(M4_DIVERSION))dnl
        divert(M4_DIVERSION)dnl
    ]]]]])dnl
]]]]])dnl
dnl
undefine([[[[[eval]]]]])dnl
dnl Copyright 2008-2018 Douglas Wikstrom
dnl
dnl This file is part of Verificatum JavaScript Cryptographic library
dnl (VJSC).
dnl
dnl VJSC is free software: you can redistribute it and/or modify it
dnl under the terms of the GNU Affero General Public License as
dnl published by the Free Software Foundation, either version 3 of the
dnl License, or (at your option) any later version.
dnl
dnl VJSC is distributed in the hope that it will be useful, but WITHOUT
dnl ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
dnl or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
dnl Public License for more details.
dnl
dnl You should have received a copy of the GNU Affero General Public
dnl License along with VJSC. If not, see <http://www.gnu.org/licenses/>.
dnl define([[[[[M4_LONG_ADD_WORDS]]]]],[[[[[dnl
dnl
dnl M4_LONG_ADD2(x1,x0,y1,y0,t)
dnl
dnl sets (x1,x0) = (x1,x0) + (y1,y0) and drops the overflow.
dnl
define([[[[[M4_LONG_ADD2]]]]],[[[[[dnl
$5 = $2 + $4;
$2 = $5 & M4_MASK_ALL;
$1 = ($1 + $3 + ($5 >>> M4_WORDSIZE)) & M4_MASK_ALL]]]]])dnl
dnl
dnl M4_LONG_ADD(x,y,t)
dnl
dnl set x = x + y and drops the overflow, where x=[x0,x1] and y=[y0,y1].
dnl
define([[[[[M4_LONG_ADD]]]]],dnl
[[[[[M4_LONG_ADD2($1[1],$1[0],$2[1],$2[0],$3)]]]]])dnl
define([[[[[M4_WORD_MUL]]]]],[[[[[dnl
$4[0] = $2;
$1[0] = 0;
$1[1] = muladd_loop($1, $4, 0, 1, $3, 0, 0)dnl
]]]]])dnl
dnl
dnl
dnl
dnl
dnl M4_WORD_MULADD2(w,x,y1,y0,c,t1,t2,t3)
dnl
dnl sets w = w + x * (y1,y0) + c and sets c = the carry
dnl
dnl t1,t2,t3 are temporary variable names that must be unique within
dnl the scope.
dnl
dnl y1 can be one bit too large in which case c may be as well.
dnl
define([[[[[M4_WORD_MULADD2]]]]],dnl
[[[[[dnl

// Extract upper and lower halves of x.
$6 = M4_HIGH($2);
$7 = M4_LOW($2);

// This implies:
// $6 < 2^M4_HALF_WORDSIZE
// $7 < 2^M4_HALF_WORDSIZE

// Compute the sum of the cross terms.
$8 = ($6 * $4 + $7 * $3) | 0;

// This implies:
// $8 < 2^(M4_WORDSIZE + 2)

dnl     For 30-bit words we need to split the carry which explains the
dnl     M4 macro at the end of the expression.
dnl
// Partial computation from which the lower word can be
// extracted.
$7 = ((($1 | 0) + $7 * $4 +
       (M4_LOW($8) << M4_HALF_WORDSIZE)) | 0) + M4_LSWORD_C($5);

// This implies: so we can safely use bit operator on $7.
// $7 < 2^(M4_WORDSIZE + 2)

// Complete the computation of the higher bits.
$5 = (($7 >>> M4_WORDSIZE) + $6 * $3 +
     M4_HIGH($8) M4_MSWORD_LONG_C($5)) | 0;

// Extract the lower word of x * y.
$1 = $7 & M4_MASK_ALL]]]]])dnl
define([[[[[M4_JSSRC]]]]],[[[[[src/js]]]]])dnl
define([[[[[M4_VJSC_VERSION]]]]],[[[[[1.1.1]]]]])dnl
define([[[[[M4_MANTISSA]]]]],[[[[[53]]]]])dnl
dnl
define([[[[[M4_WORDSIZE]]]]],[[[[[28]]]]])dnl
define([[[[[M4_TWO_POW_WORDSIZE]]]]],[[[[[0x10000000]]]]])dnl
define([[[[[M4_MASK_ALL]]]]],[[[[[0xfffffff]]]]])dnl
define([[[[[M4_MASK_MSB]]]]],[[[[[0x8000000]]]]])dnl
define([[[[[M4_MASK_LSB]]]]],[[[[[0x1]]]]])dnl
dnl
define([[[[[M4_HALF_WORDSIZE]]]]],[[[[[14]]]]])dnl
define([[[[[M4_TWO_POW_HALF_WORDSIZE]]]]],[[[[[0x4000]]]]])dnl
define([[[[[M4_HALF_MASK_ALL]]]]],[[[[[0x3fff]]]]])dnl
dnl
dnl Returns the WORDSIZE/2 lower bits of the input word.
define([[[[[M4_LOW]]]]],[[[[[($1 & M4_HALF_MASK_ALL)]]]]])dnl
dnl
dnl Returns the high part of the input word (may be more than half).
define([[[[[M4_HIGH]]]]],[[[[[($1 >>> M4_HALF_WORDSIZE)]]]]])dnl
dnl
dnl Additional tweaks needed for 30-bit words.
define([[[[[M4_LSWORD_C]]]]],[[[[[$1]]]]])dnl
define([[[[[M4_MSWORD_LONG_C]]]]],[[[[[]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/arithm.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ec.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_brainpoolp192r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_brainpoolp224r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_brainpoolp256r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_brainpoolp320r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_brainpoolp384r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_brainpoolp512r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_curves.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_P-192.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_P-224.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_P-256.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_P-384.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_P-521.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_prime192v1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_prime192v2.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_prime192v3.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_prime239v1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_prime239v3.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_prime256v1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp192k1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp192r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp224k1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp224r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp256k1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp256r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp384r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ECqPGroup_named_secp521r1.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ExpHom.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/FixModPow.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/Hom.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/LargeInteger.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_groups.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp1024.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp1536.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp2048.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp3072.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp4096.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp6144.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp768.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPGroup_named_modp8192.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/ModPowProd.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/PField.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/PGroup.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/PPGroup.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/PPRing.js]]]]])dnl
M4_ENABLE([[[[[verificatum/arithm/PRing.js]]]]])dnl
M4_ENABLE([[[[[verificatum/benchmark/benchmark.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/crypto.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ElGamal.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ElGamalZKPoKAdapter.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ElGamalZKPoK.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ElGamalZKPoKWriteIn.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/SchnorrProof.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/SigmaProofAnd.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/SigmaProof.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/SigmaProofOr.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/SigmaProofPara.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ZKPoK.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ZKPoKWriteInAdapter.js]]]]])dnl
M4_ENABLE([[[[[verificatum/crypto/ZKPoKWriteIn.js]]]]])dnl
M4_ENABLE([[[[[verificatum/verificatum.js]]]]])dnl
