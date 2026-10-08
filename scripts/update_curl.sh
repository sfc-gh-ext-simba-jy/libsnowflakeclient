#!/usr/bin/env bash
# Rebase the Snowflake curl patch onto a new upstream curl release.
#
# Usage:
#   scripts/update_curl.sh <next_version> [current_version]
#   scripts/update_curl.sh --continue      # after resolving conflicts
#
# The work happens in a throwaway git repo ($CURL_UPDATE_DIR, default
# ${TMPDIR:-/tmp}/curl-update), so the main repo never tracks deps/curl:
#   commit 1: pristine curl <current>
#   commit 2: pristine curl <next>
#   git apply --3way patches/curl-<current>.patch on top of commit 2
# <current> defaults to the version of the single patches/curl-<x.y.z>.patch.
# On success patches/curl-<next>.patch replaces the old patch.
# scripts/_init.sh / _init.bat are not read or modified.
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
PATCH_DIR="$REPO_ROOT/patches"
SF_SRC_DIR="$PATCH_DIR/curl/lib/vtls"
WORK_DIR="${CURL_UPDATE_DIR:-${TMPDIR:-/tmp}/curl-update}"
STATE_FILE="$WORK_DIR/.state"

log() { echo -e "\n==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
wgit() { git -C "$WORK_DIR" -c core.autocrlf=false -c user.name=curl-update -c user.email=curl-update@localhost "$@"; }

current_version_from_patch() {
  local patches=("$PATCH_DIR"/curl-[0-9]*.patch)
  [ -e "${patches[0]}" ] || die "no patches/curl-<version>.patch found"
  [ ${#patches[@]} -eq 1 ] || die "multiple curl patches found; pass current_version explicitly"
  basename "${patches[0]}" .patch | sed 's/^curl-//'
}

extract_curl() {
  local version=$1 tarball="$WORK_DIR/curl-$1.tar.gz"
  if [ ! -f "$tarball" ]; then
    log "Downloading curl $version"
    curl -fsSL "https://curl.se/download/curl-${version}.tar.gz" -o "$tarball"
  fi
  rm -rf "$WORK_DIR/deps/curl"
  mkdir -p "$WORK_DIR/deps"
  tar -xzf "$tarball" -C "$WORK_DIR/deps"
  mv "$WORK_DIR/deps/curl-${version}" "$WORK_DIR/deps/curl"
}

commit_curl() {
  wgit add -A -f deps/curl
  wgit commit -q -m "$1"
}

unresolved_files() {
  wgit diff --name-only --diff-filter=U
  # files staged without unmerged entries can still carry markers
  wgit diff --name-only HEAD -- deps/curl | while read -r f; do
    if grep -qE '^(<<<<<<<|>>>>>>>)( |$)' "$WORK_DIR/$f" 2>/dev/null; then echo "$f"; fi
  done
}

# Warn about curl internals used by the sf_* sources that no longer exist.
check_internals() {
  local curl_dir="$WORK_DIR/deps/curl" fail=0 s h f
  log "Checking curl internals used by $SF_SRC_DIR"
  for s in $(grep -ohE '\b(Curl_|curlx_)[A-Za-z0-9_]+' "$SF_SRC_DIR"/sf_*.c | sort -u); do
    grep -rqE "\b$s\b" "$curl_dir/lib" --include=*.h || { echo "  missing symbol: $s"; fail=1; }
  done
  for h in $(grep -ohE '#include "[^"]+"' "$SF_SRC_DIR"/sf_*.[ch] | cut -d'"' -f2 | grep -v '^sf_' | sort -u); do
    case "$h" in oobtelemetry.h) continue ;; esac
    [ -e "$curl_dir/lib/$h" ] || [ -e "$curl_dir/lib/vtls/$h" ] || { echo "  missing header: $h"; fail=1; }
  done
  for f in STRING_PROXY STRING_PROXYUSERNAME STRING_PROXYPASSWORD STRING_NOPROXY proxyport; do
    grep -q "\b$f\b" "$curl_dir/lib/urldata.h" || { echo "  missing field: $f"; fail=1; }
  done
  [ $fail -eq 0 ] && echo "  OK" || echo "  -> fix the sf_* sources before building"
}

finish() {
  local cur=$1 next=$2 new_patch="$PATCH_DIR/curl-$2.patch"

  log "Generating $new_patch"
  wgit add -A -f deps/curl
  wgit diff --cached HEAD -- deps/curl > "$new_patch"
  [ -s "$new_patch" ] || die "generated patch is empty"
  if [ "$cur" != "$next" ]; then
    rm -f "$PATCH_DIR/curl-$cur.patch"
  fi

  check_internals
  rm -f "$STATE_FILE"
  log "Done. Review: git status -- patches  (work dir kept: $WORK_DIR)"
}

stop_on_conflict() {
  echo
  echo "Conflicts to resolve in $WORK_DIR:"
  unresolved_files | sort -u | sed 's/^/  /'
  echo
  echo "Resolve them (keep upstream code + Snowflake hunks), then run:"
  echo "  scripts/update_curl.sh --continue"
  exit 1
}

# ===== --continue =====
if [ "${1:-}" = "--continue" ]; then
  [ -f "$STATE_FILE" ] || die "no update in progress ($STATE_FILE not found)"
  # shellcheck disable=SC1090
  . "$STATE_FILE"
  [ -z "$(unresolved_files)" ] || stop_on_conflict
  finish "$CUR" "$NEXT"
  exit 0
fi

# ===== start =====
NEXT=${1:-}
[ -n "$NEXT" ] || die "usage: $0 <next_version> [current_version] | --continue"
CUR=${2:-$(current_version_from_patch)}
OLD_PATCH="$PATCH_DIR/curl-$CUR.patch"
[ -f "$OLD_PATCH" ] || die "patch not found: $OLD_PATCH"
[ -f "$STATE_FILE" ] && die "update in progress in $WORK_DIR; use --continue or delete it"

log "Preparing $WORK_DIR (curl $CUR -> $NEXT)"
mkdir -p "$WORK_DIR"
find "$WORK_DIR" -mindepth 1 -maxdepth 1 ! -name 'curl-*.tar.gz' -exec rm -rf {} +
wgit init -q

extract_curl "$CUR"
commit_curl "curl $CUR"
extract_curl "$NEXT"
commit_curl "curl $NEXT"
printf 'CUR=%s\nNEXT=%s\n' "$CUR" "$NEXT" > "$STATE_FILE"

log "Applying patches/curl-$CUR.patch with 3-way merge"
# working copies on Windows may have CRLF; curl tarballs are LF
if tr -d '\r' < "$OLD_PATCH" | wgit apply --3way --whitespace=nowarn; then
  finish "$CUR" "$NEXT"
else
  stop_on_conflict
fi
