# rclone-decrypt

A self-contained decrypter for an [rclone crypt](https://rclone.org/crypt/)
directory: file contents and file and directory names, read straight from the
encrypted files on disk, with no rclone and no library. With it, a crypt needs
only its password to be read: should rclone be missing, or change its format,
this one file and a C compiler are enough.

It is one C99 file that needs only libc (with POSIX.1-2008 for directories, the
terminal and file times). Every primitive is implemented in it from its
specification, each in a section of its own that names the specification it
follows.

## Build and run

```sh
cc -O2 -o rclone-decrypt rclone-decrypt.c
./rclone-decrypt --self-test
./rclone-decrypt SRC DST                  # decrypt the tree SRC into DST
./rclone-decrypt --names SRC              # encrypted path, a tab, plain path
./rclone-decrypt --file IN OUT            # one file's contents
```

`./rclone-decrypt --help` lists every option.

## Options

The options mirror the crypt's settings in `rclone.conf`, each defaulting to
rclone's own default:

| rclone.conf                          | option                               |
| ------------------------------------ | ------------------------------------ |
| `filename_encoding = base64`         | `--encoding base64`                  |
| `filename_encoding = base32768`      | `--encoding base32768`               |
| `filename_encryption = off`          | `--names-off`                        |
| `filename_encryption = obfuscate`    | `--names-obfuscate`                  |
| `directory_name_encryption = false`  | `--no-dir-names`                     |
| `suffix = .x` (with names off)       | `--suffix .x` (`none` for no suffix) |
| `password`                           | `--password-file F`, or the terminal |
| `password2`                          | `--salt-file F`, or the terminal     |
| the values as `rclone.conf` has them | `--obscured`                         |

The password and the salt are read from the files named, their last newline
dropped, or else asked for on the terminal without echo; never from the command
line. An empty salt means rclone's default one: give `--salt-file /dev/null`
when the crypt has no `password2`. With `--obscured` both are the obscured
values copied from `rclone.conf`, revealed first as rclone does.

Each file is written to a temporary file beside its destination and renamed only
once complete, so no partial file ever has its final name; an existing file in
DST is never overwritten, but reported. Modification times are kept. A path that
fails (a name that does not decrypt, a chunk whose tag does not verify, a file
too short) is reported with its path, and the rest goes on; the exit status is
then 1, and 2 when nothing could be done at all.

## The format

As [rclone's documentation](https://rclone.org/crypt/#file-formats) describes
it, completed from rclone's source (`backend/crypt/cipher.go`) where it is
silent:

- **Keys**: [scrypt](https://www.rfc-editor.org/rfc/rfc7914) with N=16384, r=8,
  p=1 turns the password and the salt (`password2`, or a fixed default) into 80
  bytes: a 32-byte data key, a 32-byte name key and a 16-byte name tweak.
- **Contents**: `RCLONE\0\0`, a 24-byte random nonce, then the plaintext in
  chunks of 64 KiB, the last shorter, each sealed as a
  [NaCl secretbox](https://nacl.cr.yp.to/secretbox.html) (XSalsa20, then a
  16-byte [Poly1305](https://www.rfc-editor.org/rfc/rfc8439#section-2.5) tag in
  front) under the data key, the nonce incremented as a little-endian number
  after each chunk. Every tag is verified; a chunk that fails is an error naming
  the file and the chunk, and nothing of that file is kept.
- **Names**: each path segment padded with PKCS#7 to 16 bytes, enciphered with
  EME ([Halevi and Rogaway](https://eprint.iacr.org/2003/147), as
  [rfjakob/eme](https://github.com/rfjakob/eme) implements it) over
  [AES-256](https://csrc.nist.gov/pubs/fips/197/final) with the name key and
  tweak, then encoded in base32
  ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)'s hex alphabet, lower
  case, unpadded), base64 (URL alphabet, unpadded) or
  [base32768](https://github.com/qntm/base32768). Obfuscated names rotate each
  character within its class; names off keep the name and add `.bin`.
- **Obscured values** in `rclone.conf` are base64 of a 16-byte IV and the value
  under AES-CTR with a key fixed in rclone's source.
- **Name encoding of the backend**: rclone hands every backend names in its own
  encoding, in which a control character is the symbol U+2401 to U+241F that
  stands for it. The local backend on Linux writes those symbols as the control
  characters, sftp keeps them. So a base32768 name read from disk may hold
  control characters, which are read as their symbols; and a decrypted name is
  written as rclone's local backend would write it on Linux.

## Tests

`./test.sh` needs `cc` and `rclone`, and works only in a temporary directory,
with a temporary `RCLONE_CONFIG` and test passwords. It builds the tool, runs
its self-test (the known answers of RFC 7914, RFC 8439, RFC 4231, FIPS 180-4 and
FIPS-197, and of rclone's own tests), then makes 28 crypt stores with
`rclone copy` over local directories: every combination of encoding (base32,
base64, base32768), names (standard, off), directory names on and off, with and
without a salt, and obfuscated names with and without both. Each holds empty and
1-byte files, files of 65535, 65536, 65537 and 131072 bytes and of several MB,
random content, names with spaces, accents, emoji, CJK, Arabic and Hebrew,
combining marks, punctuation, control characters and the symbols that stand for
them, the longest names each mode allows on a 255-byte filesystem, 30 levels of
nesting and empty directories. Each store is decrypted and compared with the
original: the list of names and types, every file's SHA-256, every file's
modification time, and both columns of `--names`.

It also checks that the obscured values work; that a wrong password or a missing
salt fails, writing nothing but empty files (which hold no chunk to
authenticate); that a flipped byte, a bad header and a truncated chunk each fail
naming the file and the chunk, leaving no output or temporary file for it; that
existing outputs are not overwritten; and, when `uv` is present, that the
independent [rclone-crypt](https://pypi.org/project/rclone-crypt/) 1.2.0 Python
package decrypts three stores to the same files. Last it measures throughput on
a 400 MiB file.

On 2026-11-09, with rclone v1.75.2 on an Intel Xeon Gold 5515+ (Ubuntu 24.04,
GCC 13), all 168 checks passed, and the tool decrypted at about 390 MiB/s, from
and to the page cache, where `rclone cat` reached about 500 MiB/s.

## Not supported

- `no_data_encryption = true`: such files are not encrypted, and the tool
  reports them as not crypt files; copy them as they are, with `--names` for
  their names.
- Version suffixes that some backends (B2) add to encrypted names, and
  obfuscated names that hold the quoting character U+201B of rclone's name
  encoding.
- The integrity of a file as a whole: like rclone, the format authenticates each
  chunk, so a file cut exactly at a chunk boundary decrypts to its first chunks.

This tool was written independently, from rclone's documentation and, where that
is silent, its source, and checked against rclone v1.75.2.

## License

Copyright (C) 2026 Massimo Santini

rclone-decrypt is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; see [LICENSE](LICENSE) for the full text.
