
# Copyright 2008-2018 Douglas Wikstrom
#
# This file is part of Verificatum JavaScript Cryptographic library
# (VJSC).
#
# VJSC is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# VJSC is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
# Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with VJSC. If not, see <http://www.gnu.org/licenses/>.

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
