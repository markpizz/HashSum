# User Commands

Program(s) for Windows that are equivalent to Linux md5sum, sha1sum, 
sha256sum, sha384, sha512sum which generate message digests of files.

This functionality is provided by leveraging the Cryptography API 
Next Generation (CNG) library that ships with Windows versions from 
Vista onward.

# NAME
```
       md2sum              - compute and check MD2 message digests
       md4sum              - compute and check MD4 message digests
       md5sum              - compute and check MD5 message digests
       sha1sum             - compute and check SHA1 message digests
       sha256sum           - compute and check SHA256 message digests
       sha384sum           - compute and check SHA384 message digests
       sha512sum           - compute and check SHA512 message digests
       aes-cmacsum         - compute and check AES-CMAC message digests
       aes-gmacsum         - compute and check AES-GMAC message digests
       HashSum -a:HASH     - compute and check message digests with {HASH}
```
# SYNOPSIS
```
       md2sum [OPTION]... [FILE]...
       md4sum [OPTION]... [FILE]...
       md5sum [OPTION]... [FILE]...
       sha1sum [OPTION]... [FILE]...
       sha256sum [OPTION]... [FILE]...
       sha384sum [OPTION]... [FILE]...
       sha512sum [OPTION]... [FILE]...
       aes-cmacsum [OPTION]... [FILE]...
       aes-gmacsum [OPTION]... [FILE]...
       HashSum -a:HASH [OPTION]... [FILE]...
```
# DESCRIPTION
```
       Print  or check checksums.  With no FILE, or when FILE
       is -, read standard input.

       -b, --binary
              read in binary mode

       -c, --check
              read checksums from the FILEs and check them

       --tag  create a BSD-style checksum

       -t, --text
              read in text mode

       -a:HASH
              where HASH is one of these algorithms:
                SHA256,SHA384,SHA512,SHA1,MD5,MD4,MD2,AES-GMAC,AES-CMAC

   The following three options are useful only when verifying checksums:
       --quiet
              don't print OK for each successfully verified file

       --status
              don't output anything, status code shows success

       -w, --warn
              warn about improperly formatted checksum lines

       --strict
              with --check, exit non-zero for any invalid input

       --help display this help and exit

       --version
              output version information and exit

       The available checksum algorithms are computed as described in:
             SHA1,SHA256,SHA384,SHA512(FIPS-180-4)
             MD5(RFC 1321)
             MD4(RFC 1320)
             MD2(RFC 1319)
             AES-GMAC(RFC 4543)
             AES-CMAC(RFC 4493)
       When checking, the input should be a former output of this program or
       one of  the *nix programs:   md5sum, sha1sum, sha256sum, sha384sum or
       sha512sum.  The default  mode is  to  print a line  with  checksum, a
       character indicating  input  mode  ('*'  for binary, space for text),
       and name for each FILE.

```
# AUTHOR
```
       Written by Mark Pizzolato.
```
# REPORTING BUGS
```
       Report bugs to mark@infocomm.com
```
# COPYRIGHT
```
       Copyright (c) 2017 Mark Pizzolato.  All Rights Reserved.
       There is NO WARRANTY, to the extent permitted by law.

```
# Usage
```
Usage: md2sum [OPTION]... [FILE]...
Usage: md4sum [OPTION]... [FILE]...
Usage: md5sum [OPTION]... [FILE]...
Usage: sha1sum [OPTION]... [FILE]...
Usage: sha256sum [OPTION]... [FILE]...
Usage: sha384sum [OPTION]... [FILE]...
Usage: sha512sum [OPTION]... [FILE]...
Usage: aes-cmacsum [OPTION]... [FILE]...
Usage: aes-gmacsum [OPTION]... [FILE]...
Usage: hashsum -a:HASH [OPTION]... [FILE]...

Print or check checksums.
With no FILE, or when FILE is -, read standard input.

  -b, --binary    read in binary mode
  -c, --check     read checksums from the FILEs and check them
      --tag       create a BSD-style checksum
  -t, --text      read in text mode
  -a:HASH         where HASH is one of these algorithms:
                     SHA256,SHA384,SHA512,SHA1,MD5,MD4,MD2,AES-GMAC,AES-CMAC

The following five options are useful only when verifying checksums:
      --ignore-missing  don't fail or report status for missing files
      --quiet     don't print OK for each successfully verified file
      --status    don't output anything, status code shows success
      --strict    with --check, exit non-zero for any invalid input
  -w, --warn      warn about improperly formatted checksum lines

      --help      display this help and exit
      --version   output version information and exit

When checking, the input should be a former output of this program or one
of the *nix programs: md5sum, sha1sum, sha256sum, sha384sum, sha512sum.

The available checksum algorithms are computed as described in:
        SHA1,SHA256,SHA384,SHA512(FIPS-180-4)
        MD5(RFC 1321)
        MD4(RFC 1320)
        MD2(RFC 1319)
        AES-GMAC(RFC 4543)
        AES-CMAC(RFC 4493)
The default mode is to print a line with checksum, a character indicating
input mode ('*' for binary, space for text), and name for each FILE.

Report bugs to mark@infocomm.com
```