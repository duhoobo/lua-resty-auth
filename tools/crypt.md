`crypt()`
=========


[Wikipedia](http://en.wikipedia.org/wiki/Crypt_\(C\))

> `crypt` is the library function which is used to compute a password hash that
can be used to store user account passwords while keeping them relatively
secure (a passwd file). The output of the function is not simply the hash - it
is a text string which also encodes the salt (usually the first two characters
are the salt itself and the rest is the hashed result), and identifies the hash
algorithm used. This output string is what is meant for putting in a password
record which may be stored in a plain text file.
> 
> Most formally, `crypt` provides cryptographic key derivation functions for
password validation and storage on Unix systems.
>
> The same `crypt` function is used both to generate a new hash for storage and
also to hash a proffered password with a recorded salt for comparison.
> 
> Modern Unix implementations of crypt library routine support a variety of
different hash schemes. The particular hash algorithm used can be identified by
a unique code prefix in the resulting hashtext, following a pseudo-standard
called Modular Crypt Format.
> 
> Key Derivation Functions Supported by crypt:
> 
> * Traditional DES-based scheme
> * BSDi extended DES-based scheme
> * MD5-based scheme (by Poul-Henning Kamp)
> * Blowfish-based scheme
> * NT Hash Scheme
> * SHA2-based scheme
>
> The GNU C Library used by almost all Linux distributions provided an
implmentation of the `crypt` function which supported the DES, MD5 and (since
version 2.7) SHA2 based hashing algorithms methioned above.

