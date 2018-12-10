# Verificatum JavaScript Cryptography Library (VJSC)

*DO NOT EDIT! This file is generated. See Makefile.*

This library provides the cryptographic routines needed by an
electronic voting client implemented in Javascript. It is documented
in detail and considerable time has been invested in organizing the
the code.

Although this library is fast, the goal is not to be as fast as
possible, but to be fast enough and as clean and well documented as
possible. M4 macros are used for both purposes.

The library is compiled from multiple files using M4 into a single
properly formatted and indented file that encapsulates all functionality
that should not be readily accessible. Users should not add any variables
or functions to the namespaces.

This is not a general purpose library for cryptographic
software. Please read the warnings below.

This library consists of a stack of the following modules:

 * **verificatum.arithm.li** is a raw multi-precision integer
   arithmetic module. This is essentially optimized in only two
   ways; memory allocation must be handled manually, and the
   inner-most so-called "muladd" loop is optimized. Apart from this,
   it is a relatively straightforward implementation of school book
   arithmetic. References are provided for all non-trivial algorithms.

 * **verificatum.arithm.sli** provides signed multi-precision
   integer arithmetic. This is a thin layer on top of
   **verificatum.arithm.li** along with a few extra basic routines
   are are easier to implement with signed arithmetic than without,
   e.g., the extended binary greatest common divisor algorithm.

 * **verificatum.arithm.LargeInteger** provides automatic memory
   allocation on top of **verificatum.arithm.li** and
   **verificatum.arithm.sli**.

 * **verificatum.arithm.PGroup** provides abstract classes that
   capture groups of prime order.

 * **verificatum.arithm.ModPGroup** provides prime order
   subgroups modulo primes. This is a wrapper of
   **verificatum.arithm.LargeInteger** using modular arithmetic
   that provides additional utility routines.

 * **verificatum.arithm.ec** provides a raw implementation of
   elliptic curves over prime order fields of Weierstrass form using
   a variant of Jacobi coordinates. This uses the standard formulas,
   but on top of **verificatum.arithm.sli**
   (not **verificatum.arithm.LargeInteger**).

 * **verificatum.arithm.ECqPGroup** provides elliptic curve
   groups over prime order fields of Weierstrass form using a
   variant of Jacobi coordinates. In particular the standard curves
   of this form. This is a wrapper of **verificatum.arithm.ec**
   that provides automatic memory allocation and additional utility
   routines.

 * **verificatum.arithm.PField** implements a prime order field
   that may be thought of as the "exponents of a group". This is a
   wrapper of **verificatum.arithm.LargeInteger**, where computations
   take place modulo the order of the group. It also provides additional
   utility routines.

 * **verificatum.arithm.PPGroup** implements a product group
   that combines multiple groups into one to simplify computations
   over multiple group elements. The resulting group elements
   are basically glorified lists with routines that iterate over the
   individual elements. It generalizes both the arithmetic and
   utility functions to product groups.

 * **verificatum.arithm.PPRing** implements the product ring of
   a product group. We may think of this as the "ring of
   exponents". Similarly to product groups its elements are
   glorified lists of field elements along with arithmetic and
   utility routines that iterate over these elements.

A notable pattern used in the code is using static variables in
functions, where a variable is static if it survives function
invocations. This is implemented using encapsulation with immediate
functions. Static variables are re-sized as needed, but for our
application this rarely happens, so effectively we have automatic
light-weight memory allocation.

Some classes can be optionally included in the library. See
`BUILDING.md` and `Makefile` for more
information. Testing if a class is included is done using
`typeof`, e.g., the following is a
boolean that is true if and only if the class `ECqPGroup` was
included in the build.

`typeof verificatum.arithm.ECqPGroup !== "undefined"`

The function `verificatum.util.ofType` is robust as
long as the second parameter is either a string literal or a type.
To keep things consistent, we only use
`typedef variable === "undefined"` when checking for
`undefined` parameters to functions.

**WARNING! Please read the following instructions carefully.
Failure to do so may result in a completely insecure installation.**

You should NOT use this library unless you have verified the following:

 * Run all tests. JavaScript is a language with a heterogeneous set
   of available interpreters/engines. We have done our best to only
   use the most standard features, but we can not exclude the
   possibility that there are issues on any particular platform,
   since there are simply too many and they are constantly evolving.

 * Verify that the random source accessible from
   `verificatum.crypto.RandomDevice` is secure.
   A number of natural approaches are possible if this is not the
   case. We avoid all of these until we have a clear reason, since
   they bring additional complexity and potential incompatibilities
   and security issues in themselves.

**WARNING! Please read the following instructions carefully.
Failure to do so may result in a completely insecure installation.**

This library **does not protect against side channel
attacks**. Thus, this is **not** a general purpose cryptographic
library, but it is secure in electronic voting clients because of two
reasons:

 * The system is currently only used for encryption. Thus, random
   encryption exponents of the El Gamal cryptosystem are only used
   once. This effectively curtails any cache or timing attacks due
   to the lack of statistics.

 * A human being determines when encryption takes place. Thus, the
   adversary can not influence when an encryption takes place with
   sufficient granularity to execute repeated attacks.

This should be compared with, e.g., a TLS server that handles repeated
requests from a potential adversary using a fixed secret key.

Our software handles special curve points correctly and all inputs are
verified to belong to the right domain before processing. This turns
out to be particularly important for the mix-nets that process the
ciphertexts formed using this library.

However, we naturally welcome the inclusion of non-NIST curves that
are more resistant against side channel attacks. For more information
we recommend, e.g., Daniel J. Bernstein and Tanja Lange.
*SafeCurves: choosing safe curves for elliptic-curve cryptography*,
(accessed 1 December 2014).

**WARNING! Please read the following instructions carefully.
Failure to do so may result in a completely insecure installation.**

This library **does not on its own protect against attacks against
the browser or the operating system**. A short and non-exhaustive
list of threats includes:

 * Virus that corrupts the client as a whole.

 * Cross-scripting attacks.

 * Functional, memory, resource leakage between plugins or interpreters
   of the browser.

 * Weak source of randomness provided by the browser. This includes
   attempts to provide randomness by observing mouse movements (less
   relevant in a world with touch screens), or accessing external
   sites with built-in crypto libraries to harvest randomness.

It is impossible to fully protect a client against such attacks. We
can only reduce the risk in different ways.

However, electronic voting systems typically provide mechanisms at the
cryptographic protocol level to allow the voter or auditors to verify
that the right vote is encrypted.

Thus, these risks are "only" relevant for privacy if the rest of the
system is implemented properly.
