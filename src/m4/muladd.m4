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
