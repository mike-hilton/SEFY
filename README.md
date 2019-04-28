# SEFY 
*"Simple Encryption For You"*

This is a small Linux utility _(<800 lines of code)_ used for public key encryption, based on [Libsodium](https://download.libsodium.org/doc/).
It is capable of generating and saving a key pair (private- and public key), use them to encrypt and decrypt files, and also perform a secure overwrite of the original file's content.

## Purpose
Function as a lightweight encryption utility where the binary and the user's public key could be distributed to different systems to be used for encrypting files without the need to expose a password or private key to that system.

## How to
[![asciicast](https://asciinema.org/a/Chv2QPLtIhfjUSHY8g6W4CAh0.svg)](https://asciinema.org/a/Chv2QPLtIhfjUSHY8g6W4CAh0)

## Encryption
This utility uses Libsodium that is a fork of [NaCl](http://nacl.cr.yp.to/). It utilize [XSalsa20](https://en.wikipedia.org/wiki/Salsa20#XSalsa20_with_192-bit_nonce) for public key encryption and [Poly1305](https://en.wikipedia.org/wiki/Poly1305) for data integrity.

## Requirements
SEFY depends on the Libsodium library.

To compile it on Ubuntu or Debian, either _apt-get install libsodium-dev_ or [follow their instructions](https://libsodium.gitbook.io/doc/installation).
To use a compiled version of SEFY, simply _apt-get install libsodium23_ to install the Libsodium library.

## Compability
This utility has been tested on Ubuntu 18.04.2 and Debian 9.

## Why not GPG?
Well, I do actually recommend you to use GPG for public key encryption and not this tool! The creating of this utility was primarily an exercise in C for the author and only intended to be a small and easy to use utility.

## Warning
This code has not been audited and should be used with care.
