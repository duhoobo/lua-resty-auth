Excerpts from [A Future-Adaptable Password Scheme](https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf)


In the following, we give a brief overview of two password hashing functions in
widespread use today, and state their main differences from bcrypt. 



Traditional crypt
-----------------

Traditional crypt(3)'s design rationale dates back to 1976 [9]. It uses a
password of up to eight characters as a key for DES [10]. The 56-bit DES key
is formed by combining the low-order 7 bits of each character in the password.
If the password is shorter than 8 characters, it is padded with zero bits on
the right.

A 12-bit salt is used to perturb the DES algorithm, so that the same password
plaintext can produce 4,096 possible password encryptions. A modification to
the DES algorithm, swapping bits i and i+24 in the DES E-Box output when bit i
is set in the salt, achieves this while also making DES encryption hardware
useless for password guessing.

The 64-bit constant ``0`` is encrypted 25 times with the DES key. The final
output is the 12-bit salt concatenated with the encrypted 64-bit value. The
resulting 76-bit value is recoded into 13 printable ASCII characters.

At the time traditional crypt was conceived, it was fast enough for
authentication but too costly for password guessing to be practical. Today, we
are aware that it exhibits three serious limitations: the restricted password
space, the small salt space, and the constant execution cost. In contrast,
bcrypt allows for longer passwords, has salts large enough to be unique over
all time, and has adaptable cost. These limitiations therefore do not apply to
bcrypt. 



MD5 crypt
---------


MD5 crypt was written by Poul-Henning Kamp for FreeBSD. The main reason for
using MD5 was to avoid problems with American export prohibitions on
cryptographic products, and to allow for a longer password length than the 8
characters used by DES crypt. The password length is restricted only by MD5's
maximum message size of 264 bits. The salt can vary from 12 to 48 bits.

MD5 crypt hashes the password and salt in a number of different combinations
to slow down the evaluation speed. Some steps in the algorithm make it
doubtful that the scheme was designed from a cryptographic point of view--for
instance, the binary representation of the password length at some point
determines which data is hashed, for every zero bit the first byte of the
password and for every set bit the first byte of a previous hash computation.

The output is the concatenation of the version identifier ``$1$``, the salt, 
a ``$`` separator, and the 128-bit hash output.

MD5 crypt places virtually no limit on the size of passwords, while bcrypt has
a maximum of 55 bytes. We do not consider this a serious limitation of bcrypt,
however. Not only are users unlikely to choose such long passwords, but if
they did, MD5 crypt's 128-bit output size would become the limiting factor in
security. A brute force attacker could more easily find short strings hashing
to the same value as a user's password than guess the actual password.
Finally, like DES crypt, MD5 crypt has fixed cost. 

