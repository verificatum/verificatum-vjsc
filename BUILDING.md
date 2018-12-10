

                     BUILD LIBRARY

This library requires emacs to indent files. You can edit
tools/compilejs to remove this dependency.

This software can built using:

$ make <target>

where <target> is one of:

[all]      - All the below.
vjsc       - Library in standard form.
min-vjsc   - Library without comments and redundant newlines.
api-vjsc   - API for the library including browsable source code.
bench-vjsc - HTML files for running benchmarks in a browser.

The resulting libraries ends up in js/ and are named using the prefix
"vjsc-", e.g., vjsc-1.1.0.js. The the API ends up in api-vjsc and the
benchmark ends up in bench-vjsc. Tar-balls are also built.


                OPTIONAL CLASSES AND GROUPS

The library can be built to include different sets of standard groups
and implementations multiplicative groups, fixed basis exponentiations
in multiplicative groups, and elliptic curve groups. Consult the
Makefile for more information.


                       CHECK LIBRARY

The unit tests for the standard and minimized forms are run using:

$ make check

or

$ make checkminimized

This runs the test suite for the standard wordsize. You can also run
all tests for all valid wordsizes using ./tools/check_wordsizes. This
is a great way to ensure that algorithms are sound, since it exposes
corner cases.


               STATIC ANALYSIS AND COVERAGE

You can also run some syntatical checking and static analysis of the
code using jshint or eslint with:

$ make jshint

or

$ make eslint

or you can generate a unified analysis using

$ make analysis

but all of this obviously requires that JSHint and/or ESLint are
installed. There are rulesets in tools/staticanalysis/<tool>, but
there are also a few suppressions in the code. You can grep for them
with jshint and eslint.


                REMARK ON BUILDING TOOLS

Developers may find the use of macros and shell script to generate
code surprising. This is a deliberate decision and not a failure to
consider various tools and frameworks available.

Note that the code to be tested and audited in a real application is
the *generated* code that is actually executed. Tracking changes in it
can be done using various tools, e.g., using versioning tools or
diff/grep, so in fact there is a strict gain in security in our
approach and we are willing to pay a high price for security.

We need our code to be as clean as possible, with no dependencies, and
with as strong encapsulation as possible. Thus, we have opted on
generating a *single* file. It would be horrible to develop software
in a single file of course, so we needed a mechanism for including
files. We also needed users to be able to remove modules, but in a way
that results in a static single file. There is no proper include
system for JavaScript, so we built minimal tools.

Using constants instead of variables is important for speed, but the
code must be readable. In recent versions of JavaScript there is
"const" and "let". We have opted for M4 macros instead that are
replaced by the literal constants.

There are clearly pros and cons of our approach, and we are not
entirely happy with it. We welcome a constructive discussion with
readers that have ideas on how to improve or replace our approach
entirely.
