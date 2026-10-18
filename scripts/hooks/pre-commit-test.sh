#!/usr/bin/env bash
# Behavior tests for the pre-commit token-budget hook. Each case stages a
# snapshot and asserts the hook's verdict. Run: bash scripts/hooks/pre-commit-test.sh
set -eu

HOOK="$(cd "$(dirname "$0")" && pwd)/pre-commit"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

repo() {
    rm -rf "$WORK/repo"
    mkdir -p "$WORK/repo"
    cd "$WORK/repo"
    git init -q .
    git config user.email test@example.com
    git config user.name test
    printf 'seed\n' > seed.txt
    git add seed.txt
    git commit -q -m seed
    OUT="$WORK/out"
}

# fill <path> <bytes> writes a text file of exactly that size.
fill() {
    mkdir -p "$(dirname "$1")"
    head -c "$2" /dev/zero | tr '\0' 'a' > "$1"
}

check() {
    local want="$1" name="$2"
    shift 2
    local rc=0
    env "$@" "$HOOK" >"$OUT" 2>&1 || rc=$?
    if [ "$rc" -eq "$want" ]; then
        PASS=$((PASS + 1))
        printf 'ok   %s\n' "$name"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s. want rc=%s, got %s\n' "$name" "$want" "$rc"
        sed -n '1,8p' "$OUT"
    fi
}

assert_report() {
    local needle="$1" name="$2"
    if grep -qF -- "$needle" "$OUT"; then
        PASS=$((PASS + 1))
        printf 'ok   %s\n' "$name"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s. report lacks: %s\n' "$name" "$needle"
    fi
}

repo
fill small.txt 1000
git add small.txt
check 0 "a small new file commits"
git commit -q -m small

fill exact.rs 20000
git add exact.rs
check 0 "20000 B is 5000 tokens and commits"

fill over.rs 20004
git add over.rs
check 1 "20004 B is 5001 tokens and is refused"
assert_report "over.rs" "the refusal names the file"
assert_report "Split it on responsibility" "the refusal carries the split recipe"
assert_report "git commit --no-verify" "the refusal names the escape hatch"
git reset -q over.rs

fill Cargo.lock 200000
git add Cargo.lock
check 0 "a 200 KB lockfile is exempt"

fill vendor/dep.rs 200000
git add vendor/dep.rs
check 0 "a vendored source file is exempt"

fill web/app.min.js 200000
git add web/app.min.js
check 0 "a minified bundle is exempt"

head -c 200000 /dev/urandom > blob.bin
git add blob.bin
check 0 "a binary blob is exempt"

fill LICENSE 200000
git add LICENSE
check 0 "a licence text is exempt"

fill pkgs/s/skillranker/Cargo.lock.pathdeps 200000
git add pkgs/s/skillranker/Cargo.lock.pathdeps
check 0 "a generated lockfile with a suffix is exempt"

git commit -q -m exempt
mkdir -p gen
printf 'gen/deep.rs linguist-generated=true\n' > .gitattributes
git add .gitattributes
git commit -q -m attrs
fill gen/deep.rs 200000
git add gen/deep.rs
check 0 "a linguist-generated file is exempt"

fill huge.rs 300000
git add huge.rs
git commit -q --no-verify -m huge
printf 'a' >> huge.rs
git add huge.rs
check 1 "an over-budget file that grows is refused"

printf 'seed\n' > huge.rs
fill huge.rs 250000
git add huge.rs
check 0 "an over-budget file that shrinks commits"

fill wide.rs 300000
git add wide.rs
check 0 "NAU_TOKEN_BUDGET raises the limit" NAU_TOKEN_BUDGET=100000
check 1 "NAU_TOKEN_BUDGET_STRICT refuses hidden debt" NAU_TOKEN_BUDGET_STRICT=1
git reset -q wide.rs
rm -f wide.rs

printf '\npass=%s fail=%s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
