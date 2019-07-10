dnl Copyright 2008-2019 Douglas Wikstrom
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

define([[[[[M4_LONG_ADD_WORDS]]]]],[[[[[dnl
\$5 = (\$1|0) + (\$3|0);
\$1 = \$5 & M4_MASK_ALL;
\$2 = ((\$2|0) + (\$4|0) + (\$5 >>> M4_WORDSIZE)) & M4_MASK_ALL]]]]])dnl
dnl define([[[[[M4_LONG_ADD_WORDS]]]]],[[[[[dnl
dnl \$5 = \$1 + \$3;
dnl \$1 = \$5 & M4_MASK_ALL;
dnl \$2 = (\$2 + \$4 + (\$5 >>> M4_WORDSIZE)) & M4_MASK_ALL]]]]])dnl
define([[[[[M4_LONG_ADD]]]]],dnl
[[[[[M4_LONG_ADD_WORDS(\$1[0],\$1[1],\$2[0],\$2[1],\$3)]]]]])dnl
define([[[[[M4_MUL_WORD]]]]],[[[[[dnl
\$4[0] = \$2;
\$1[0] = 0;
\$1[1] = muladd_loop(\$1, \$4, 0, 1, \$3, 0, 0)dnl
]]]]])dnl
dnl \$5 = \$1 + \$3;
dnl \$1 = \$5 & M4_MASK_ALL;
dnl \$2 = (\$2 + \$4 + (\$5 >>> M4_WORDSIZE)) & M4_MASK_ALL]]]]])dnl
