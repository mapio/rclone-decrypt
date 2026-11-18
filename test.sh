#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Massimo Santini

# Prove rclone-decrypt against rclone: build it, encrypt trees with rclone
# under every combination of crypt options, decrypt them with the tool and
# compare every name and every byte with the originals. Test passwords only,
# in temporary directories, with a temporary RCLONE_CONFIG.
# Needs cc and rclone; uses uv, if present, for an independent cross-check.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/rclone-decrypt-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
export RCLONE_CONFIG=$work/rclone.conf RCLONE_CACHE_DIR=$work/cache
: >"$RCLONE_CONFIG"
export LC_ALL=C

passes=0 failures=0
ok() { passes=$((passes + 1)); }
fail() {
  failures=$((failures + 1))
  echo "FAIL: $*" >&2
}
check() {
  local what=$1
  shift
  if "$@"; then ok; else fail "$what"; fi
}
# Run the tool expecting failure: status non-zero and stderr matching $1.
expect_error() {
  local what=$1 pattern=$2 status=0
  shift 2
  "$@" 2>"$work/stderr" >/dev/null || status=$?
  if [ "$status" -ne 0 ] && grep -q -- "$pattern" "$work/stderr"; then
    ok
  else
    fail "$what (status $status, stderr: $(head -3 "$work/stderr"))"
  fi
}

echo "== build"
tool=$work/rclone-decrypt
cc -O2 -o "$tool" "$here/rclone-decrypt.c"
warnings=$(cc -std=c99 -pedantic -Wall -Wextra -O2 -o /dev/null \
  "$here/rclone-decrypt.c" 2>&1 | grep -c 'warning:' || true)
echo "built; $warnings warnings under -std=c99 -pedantic -Wall -Wextra"
check "self-test" "$tool" --self-test

# The tree every store holds. Its names must survive rclone's local backend
# unchanged, so: valid UTF-8, no control characters.
plain=$work/plain
mkfile() {
  mkdir -p "$(dirname "$1")"
  head -c "$2" /dev/urandom >"$1"
}
rep() { # rep STRING COUNT
  local s="" i
  for ((i = 0; i < $2; i++)); do s+=$1; done
  printf '%s' "$s"
}
mkfile "$plain/empty" 0
mkfile "$plain/one byte" 1
mkfile "$plain/chunk-65535" 65535
mkfile "$plain/chunk-65536" 65536
mkfile "$plain/chunk-65537" 65537
mkfile "$plain/chunk-131072" 131072
mkfile "$plain/several MB.bin" $((5 * 1048576 + 12345))
mkfile "$plain/spaces  in   the name .txt" 100
mkfile "$plain/accénts àèìòù ÄÖÜ ß ñ ç.txt" 200
mkfile "$plain/emoji 😀🎉🐍 ✓.txt" 300
mkfile "$plain/日本語のファイル名.txt" 400
mkfile "$plain/العربية والعبرית.txt" 500
mkfile "$plain/combining é and precomposed é.txt" 600
mkfile "$plain/punctuation '\"&;\$#%*?:<>|\\ ~ {} [] () .txt" 700
mkfile "$plain/bang!name!!.txt" 800
mkfile "$plain/"$'control \x01 \x1f \r del \x7f end' 850
mkfile "$plain/symbols ␍ ␡ ␀" 860
mkfile "$plain/.hidden" 900
mkfile "$plain/Ελληνικά και Кириллица/файл.dat" 1000
mkfile "$plain/a/b/same name" 10
mkfile "$plain/a/same name" 20
mkfile "$plain/$(rep x 143)" 30
mkfile "$plain/$(rep é 71)x" 40
mkfile "$plain/$(rep 😀 35)abc" 50
deep=$plain
for i in $(seq -w 1 30); do deep+="/level $i ü"; done
mkfile "$deep/deep file" 4321
mkdir -p "$plain/empty dir" "$plain/nested/empty/inner empty" \
  "$plain/vide é 😀"

# What a tree holds: every entry with its type, then every file's sha256.
manifest() {
  (
    cd "$1"
    find . -mindepth 1 -printf '%y %P\n' | sort
    find . -type f -printf '%P\0' | sort -z | xargs -0r sha256sum --
  )
}
# Files' modification times, which the tool keeps from the encrypted files.
mtimes() { (cd "$1" && find . -type f -printf '%T@ %P\n' | sort -k2); }
# Paths as --names prints them: directories with a final '/'.
listing() {
  (cd "$1" && find . -mindepth 1 \( -type d -printf '%P/\n' \) -o -printf '%P\n') \
    | sort
}
same() { cmp -s "$1" "$2"; }

pw='correct horse ☃ battery staple'
salt='pepper & salt ✓'
printf '%s\n' "$pw" >"$work/password"
printf '%s\n' "$salt" >"$work/salt"
rclone obscure "$pw" >"$work/password.obscured"
rclone obscure "$salt" >"$work/salt.obscured"
printf '%s\n' 'not the password' >"$work/wrong"

# The longest name each mode allows on a local filesystem (255 bytes).
max_name() { # max_name NAMES ENCODING
  case $1/$2 in
    standard/base64) echo 175 ;;
    standard/*) echo 143 ;;
    off/*) echo 251 ;;
    obfuscate/*) echo 250 ;;
  esac
}

# make_store NAME NAMES ENCODING DIRNAMES SALT(yes|no) SOURCE
make_store() {
  local name=$1
  {
    echo "[$name]"
    echo "type = crypt"
    echo "remote = $work/stores/$name"
    echo "password = $(cat "$work/password.obscured")"
    [ "$5" = yes ] && echo "password2 = $(cat "$work/salt.obscured")"
    echo "filename_encryption = $2"
    echo "directory_name_encryption = $4"
    echo "filename_encoding = $3"
    echo
  } >>"$RCLONE_CONFIG"
  mkdir -p "$work/stores/$name"
  rclone copy --create-empty-src-dirs "$6" "$name:"
}

# decrypt_args NAMES ENCODING DIRNAMES SALT: the tool's options
decrypt_args() {
  args=(--password-file "$work/password" --encoding "$2")
  if [ "$4" = yes ]; then
    args+=(--salt-file "$work/salt")
  else args+=(--salt-file /dev/null); fi
  [ "$1" = off ] && args+=(--names-off)
  [ "$1" = obfuscate ] && args+=(--names-obfuscate)
  [ "$3" = false ] && args+=(--no-dir-names)
  return 0
}

echo "== every combination of options"
combos=()
for names in standard off; do
  for enc in base32 base64 base32768; do
    for dirn in true false; do
      for s in yes no; do combos+=("$names $enc $dirn $s"); done
    done
  done
done
for dirn in true false; do
  for s in yes no; do combos+=("obfuscate base32 $dirn $s"); done
done

for combo in "${combos[@]}"; do
  read -r names enc dirn s <<<"$combo"
  name="$names-$enc-dirs_$dirn-salt_$s"
  src=$work/src/$name
  mkdir -p "$work/src"
  cp -al "$plain" "$src"
  m=$(max_name "$names" "$enc")
  mkfile "$src/$(rep D "$m")/$(rep f "$m")" 77
  mkfile "$src/$(rep ü $(((m - 1) / 2)))$(rep x $((m - (m - 1) / 2 * 2)))" 88
  make_store "$name" "$names" "$enc" "$dirn" "$s" "$src"

  decrypt_args "$names" "$enc" "$dirn" "$s"
  out=$work/out/$name
  if "$tool" "${args[@]}" "$work/stores/$name" "$out"; then
    ok
  else
    fail "$name: decryption failed"
    continue
  fi
  manifest "$src" >"$work/m.src"
  manifest "$out" >"$work/m.out"
  check "$name: names and contents" same "$work/m.src" "$work/m.out"
  mtimes "$src" >"$work/t.src"
  mtimes "$out" >"$work/t.out"
  check "$name: modification times" same "$work/t.src" "$work/t.out"

  "$tool" --names "${args[@]}" "$work/stores/$name" >"$work/names"
  cut -f2 "$work/names" | sort >"$work/names.dec"
  cut -f1 "$work/names" | sort >"$work/names.enc"
  listing "$src" >"$work/l.src"
  listing "$work/stores/$name" >"$work/l.store"
  check "$name: --names decrypted column" same "$work/names.dec" "$work/l.src"
  check "$name: --names encrypted column" same "$work/names.enc" \
    "$work/l.store"
  echo "$name: $(wc -l <"$work/l.src") paths"
done

std=standard-base32-dirs_true-salt_yes
off=off-base32-dirs_true-salt_yes
decrypt_args standard base32 true yes

echo "== obscured values"
"$tool" --obscured --password-file "$work/password.obscured" \
  --salt-file "$work/salt.obscured" "$work/stores/$std" "$work/obscured"
manifest "$work/obscured" >"$work/m.obs"
manifest "$work/out/$std" >"$work/m.std"
check "--obscured gives the same tree" same "$work/m.obs" "$work/m.std"

echo "== wrong secrets"
expect_error "wrong password, standard names" "cannot decrypt the name" \
  "$tool" --password-file "$work/wrong" --salt-file "$work/salt" \
  "$work/stores/$std" "$work/wrong-std"
check "wrong password writes no file" \
  test -z "$(find "$work/wrong-std" -type f)"
expect_error "wrong password, names off" "fails authentication" \
  "$tool" --password-file "$work/wrong" --salt-file "$work/salt" \
  --names-off "$work/stores/$off" "$work/wrong-off"
check "wrong password, names off, writes only empty files" \
  test -z "$(find "$work/wrong-off" -type f -size +0)"
expect_error "missing salt" "cannot decrypt the name" \
  "$tool" --password-file "$work/password" --salt-file /dev/null \
  "$work/stores/$std" "$work/nosalt"
expect_error "wrong encoding" "not in the name encoding" \
  "$tool" "${args[@]}" --encoding base64 \
  "$work/stores/standard-base32768-dirs_true-salt_yes" "$work/wrongenc"

echo "== damaged files"
corrupt=$work/corrupt
cp -a "$work/stores/$std" "$corrupt"
enc_of() { # the encrypted path of a plaintext path, from --names
  awk -F'\t' -v p="$1" '$2 == p { print $1 }' "$work/names.$std"
}
"$tool" --names "${args[@]}" "$corrupt" >"$work/names.$std"
flip() { # flip FILE OFFSET: change one bit of one byte
  local b
  b=$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' ')
  printf "$(printf '\\%03o' $((b ^ 1)))" \
    | dd of="$1" bs=1 seek="$2" conv=notrunc status=none
}
big=$(enc_of "several MB.bin")
flip "$corrupt/$big" $((32 + 65552 * 3 + 1000))
magic=$(enc_of "chunk-65536")
flip "$corrupt/$magic" 0
short=$(enc_of "chunk-65537")
truncate -s 42 "$corrupt/$short"
tag=$(enc_of "one byte")
flip "$corrupt/$tag" 32
expect_error "corrupted chunk named" "$big: chunk 3 .* fails authentication" \
  "$tool" "${args[@]}" "$corrupt" "$work/corrupt-out"
grep -q -- "$magic: not an rclone crypt file" "$work/stderr" && ok \
  || fail "bad magic reported"
grep -q -- "$short: chunk 0 is truncated" "$work/stderr" && ok \
  || fail "truncated file reported"
grep -q -- "$tag: chunk 0 .* fails authentication" "$work/stderr" && ok \
  || fail "corrupted tag reported"
for f in "several MB.bin" chunk-65536 chunk-65537 "one byte"; do
  check "no output for damaged '$f'" test ! -e "$work/corrupt-out/$f"
done
check "no temporary file left" \
  test -z "$(find "$work/corrupt-out" -name '.rclone-decrypt.*')"
check "undamaged files still decrypted" \
  cmp -s "$plain/chunk-131072" "$work/corrupt-out/chunk-131072"

echo "== single files, existing outputs, bad arguments"
"$tool" --file "${args[@]}" "$work/stores/$std/$big" "$work/single"
check "--file" cmp -s "$plain/several MB.bin" "$work/single"
expect_error "--file refuses an existing output" "already exists" \
  "$tool" --file "${args[@]}" "$work/stores/$std/$big" "$work/single"
expect_error "an existing tree is not overwritten" "already exists" \
  "$tool" "${args[@]}" "$work/stores/$std" "$work/out/$std"
manifest "$work/out/$std" >"$work/m.again"
check "existing tree unchanged" same "$work/m.std" "$work/m.again"
expect_error "DST inside SRC" "must not be inside" \
  "$tool" "${args[@]}" "$work/stores/$std" "$work/stores/$std/x"
expect_error "unknown option" "unknown option" "$tool" --bogus a b

if command -v uv >/dev/null; then
  echo "== cross-check with the rclone-crypt Python package"
  cat >"$work/xcheck.py" <<'EOF'
import os, sys
from rclone import Crypt
store, out, pw, salt, encoding = sys.argv[1:]
c = Crypt(pw, salt, name_encoding=encoding)
# rclone's local backend writes the symbols U+2401-U+241F and U+2421 of its
# Standard name encoding as control characters; rclone-crypt knows nothing
# of that layer, so it is applied here around it.
def symbol(ch):
    return 0x2401 <= ord(ch) <= 0x241F or ch == "\u2421"
def to_standard(s):
    return "".join(chr(ord(ch) + 0x2400) if 1 <= ord(ch) <= 0x1F
                   else "\u2421" if ch == "\x7f" else ch for ch in s)
def to_local(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\u201b" and i + 1 < len(s) and symbol(s[i + 1]):
            out.append(s[i + 1]); i += 2
        elif symbol(s[i]):
            out.append("\x7f" if s[i] == "\u2421" else chr(ord(s[i]) - 0x2400)); i += 1
        else:
            out.append(s[i]); i += 1
    return "".join(out)
for root, dirs, files in os.walk(store):
    for f in files:
        rel = to_standard(os.path.relpath(os.path.join(root, f), store))
        dst = os.path.join(out, to_local(c.Name.standard_decrypt(rel)))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        c.File.file_decrypt(os.path.join(root, f), dst)
EOF
  files() {
    (cd "$1" && find . -type f -printf '%P\0' | sort -z | xargs -0r sha256sum --)
  }
  for enc in base32 base64 base32768; do
    name=standard-$enc-dirs_true-salt_yes
    if uv run -q --no-project --with rclone-crypt==1.2.0 python -I \
      "$work/xcheck.py" "$work/stores/$name" "$work/py-$enc" "$pw" "$salt" \
      "$enc"; then
      files "$work/py-$enc" >"$work/f.py"
      files "$work/out/$name" >"$work/f.tool"
      check "rclone-crypt agrees on $name" same "$work/f.py" "$work/f.tool"
    else
      fail "rclone-crypt could not decrypt $name"
    fi
  done
else
  echo "== uv not found: no cross-check with rclone-crypt"
fi

echo "== throughput"
perf=$work/perf
mkfile "$perf/big" $((400 * 1048576))
make_store perf standard base32 true no "$perf"
encbig=$(find "$work/stores/perf" -type f)
now() { date +%s.%N; }
t0=$(now)
"$tool" --file --password-file "$work/password" --salt-file /dev/null \
  "$encbig" "$work/perf.out"
t1=$(now)
rclone cat perf:big >/dev/null
t2=$(now)
check "400 MiB file" cmp -s "$perf/big" "$work/perf.out"
awk -v a="$t0" -v b="$t1" -v c="$t2" 'BEGIN {
  printf "rclone-decrypt: %.0f MiB/s (rclone cat: %.0f MiB/s)\n",
    400 / (b - a), 400 / (c - b) }'

echo "== $passes passed, $failures failed"
[ "$failures" -eq 0 ]
