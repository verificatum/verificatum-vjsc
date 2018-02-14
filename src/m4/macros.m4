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
