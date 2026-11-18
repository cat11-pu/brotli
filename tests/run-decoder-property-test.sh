#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-"$root/artifacts/decoder_property"}"
cc="${CC:-cc}"
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/brotli-property.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT

mapfile -t sources < <(
  find "$root/c/common" "$root/c/dec" "$root/c/enc" -name '*.c' -print | sort
)

cflags=(
  -std=c99 -O1 -g -fno-omit-frame-pointer -fstack-protector-strong
  -fsanitize=address,undefined -I"$root/c/include"
)
mkdir -p "$build_dir/obj"
objects=()
pids=()

for src in "${sources[@]}"; do
  object="$build_dir/obj/$(printf '%s' "$src" | tr '/' '_').o"
  objects+=("$object")
  "$cc" "${cflags[@]}" -c "$src" -o "$object" &
  pids+=("$!")
done
object="$build_dir/obj/decoder_property_test.o"
objects+=("$object")
"$cc" "${cflags[@]}" -c "$root/tests/decoder_property_test.c" -o "$object" &
pids+=("$!")

compile_status=0
for pid in "${pids[@]}"; do
  wait "$pid" || compile_status=1
done
if [[ "$compile_status" -ne 0 ]]; then
  exit "$compile_status"
fi

"$cc" \
  -fsanitize=address,undefined \
  "${objects[@]}" \
  -lm \
  -o "$build_dir/decoder_property_test"

rm -rf "$out"
mkdir -p "$out"

ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:halt_on_error=1:strict_string_checks=1:check_initialization_order=1:detect_stack_use_after_return=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
LSAN_OPTIONS="exitcode=23" \
DECODER_PROPERTY_SANITIZER="address,undefined" \
  "$build_dir/decoder_property_test" \
    --fixtures "$root/tests/testdata" \
    --out "$out"
