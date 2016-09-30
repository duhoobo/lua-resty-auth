#!/usr/bin/env python
import base64
import getpass
import hashlib
import os

salt = os.urandom(8)

print '{SSHA}' + base64.b64encode(
    hashlib.sha1(getpass.getpass() + salt).digest() + salt)
