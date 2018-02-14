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
