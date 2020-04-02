dnl Copyright 2008-2020 Douglas Wikstrom
dnl
dnl This file is part of Verificatum JavaScript Cryptographic library
dnl (VJSC).
dnl
dnl Permission is hereby granted, free of charge, to any person
dnl obtaining a copy of this software and associated documentation
dnl files (the "Software"), to deal in the Software without
dnl restriction, including without limitation the rights to use, copy,
dnl modify, merge, publish, distribute, sublicense, and/or sell copies
dnl of the Software, and to permit persons to whom the Software is
dnl furnished to do so, subject to the following conditions:
dnl
dnl The above copyright notice and this permission notice shall be
dnl included in all copies or substantial portions of the Software.
dnl
dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
dnl EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
dnl MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
dnl NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
dnl BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
dnl ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
dnl CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
dnl SOFTWARE.
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
