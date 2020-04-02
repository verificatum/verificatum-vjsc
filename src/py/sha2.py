
# Copyright 2008-2020 Douglas Wikstrom
#
# This file is part of Verificatum JavaScript Cryptographic library
# (VJSC).
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Computes test vectors for SHA-2 using Python that are used to test
the JavaScript implementation, and outputs a JavaScript list of pairs
of messages and digests.
"""

import hashlib

s = "abcdefghijklmnopqrstuvwxyzwABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
s = s * 5

messages = []
digests = []

print "var sha256_teststrings = ["

for i in range(0, len(s)):
    m = s[0:i]
    messages.append(m)

    h = hashlib.sha256()
    h.update(m)
    md = h.hexdigest()
    digests.append(md)

    print "[\"%s\", \"%s\"]," % (m, md)

print "];"
