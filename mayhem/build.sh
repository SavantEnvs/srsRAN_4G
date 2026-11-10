#!/usr/bin/env bash
#
# mayhem/build.sh — build the srsRAN_4G fuzz harnesses (sanitized, DWARF 3) and the oracle (normal flags).
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, with no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Three UBSan checks fire on benign patterns throughout the generated ASN.1 code and would halt almost every
# malformed message: `enum` (raw decoded values are stored in plain enums that name only a few of them),
# `null` (dyn_array::operator[] binds a reference to the null data pointer of an empty array, never reading
# it; real null dereferences still fault under ASan) and `bool` (ext_groups_unpacker_guard reads the flags
# of a freshly allocated dyn_array<bool>). The rest of UBSan stays on and halting.
SAN_FLAGS="$SANITIZER_FLAGS -fno-sanitize=enum,null,bool"

TARGETS="fuzz_eps_nas fuzz_nas_5g fuzz_rrc_lte fuzz_rrc_nr fuzz_s1ap fuzz_ngap fuzz_e2ap fuzz_rlc_am fuzz_mac_nr fuzz_gtpu"

# Static libraries (cmake target names) the harnesses and the KAT probe link against.
LIB_TARGETS="srsran_mac srsran_common srsran_phy srsran_rlc srsran_gtpu srsran_asn1 rrc_asn1 rrc_nr_asn1 ngap_nr_asn1 s1ap_asn1 ric_e2 nas_5g_msg asn1_utils support srslog"

# Only the library code is built from the CMake tree (no srsUE/srsENB/srsEPC, no RF, no GUI).
CMAKE_COMMON=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  -DENABLE_WERROR=OFF -DENABLE_SRSUE=OFF -DENABLE_SRSENB=OFF -DENABLE_SRSEPC=OFF
  -DENABLE_GUI=OFF -DENABLE_ZEROMQ=OFF -DENABLE_ALL_TEST=OFF
  -DAUTO_DETECT_ISA=OFF -DDISABLE_SIMD=ON -DGCC_ARCH=x86-64
)
CXX_QUIRK="-Wno-missing-template-arg-list-after-template-kw"

# A CMake tree configured with a different compiler path (the image build runs under a compile-cache
# wrapper, a plain re-run resolves clang directly) is wiped and reconfigured by CMake without the -D options,
# so start such a tree from scratch.
fresh_if_compiler_changed() {
  local cache="$1/CMakeCache.txt"
  if [ -f "$cache" ] && ! grep -qxF "CMAKE_CXX_COMPILER:FILEPATH=$(command -v "$CXX")" "$cache"; then
    rm -rf "$1"
  fi
}

# 1) Sanitized library build for the harnesses. -fsanitize=fuzzer-no-link gives the library SanCov
#    edge instrumentation; the harness links the libFuzzer runtime.
FUZZ_FLAGS="$SAN_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
B="$SRC/mayhem/build-fuzz"
fresh_if_compiler_changed "$B"
cmake -S "$SRC" -B "$B" "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" \
  -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS $CXX_QUIRK" \
  -DCMAKE_C_FLAGS_RELEASE="-O1 -DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-O1 -DNDEBUG"
# shellcheck disable=SC2086
cmake --build "$B" -j"$MAYHEM_JOBS" --target $LIB_TARGETS

# 2) Harnesses: a libFuzzer binary and a -standalone reproducer each.
LIBS=()
for t in $LIB_TARGETS; do
  f="$(find "$B/lib" -name "lib$t.a" | head -n1)"
  [ -n "$f" ] || { echo "missing lib$t.a" >&2; exit 1; }
  LIBS+=("$f")
done
SYS_LIBS=(-lmbedcrypto -lfftw3f -lpthread -lm -latomic)
HARNESS_INC=(-I"$SRC/lib/include" -I"$B/lib/include" -I"$SRC/mayhem")
HARNESS_FLAGS=(-std=c++14 -fno-strict-aliasing -DBUILD_TYPE_RELEASE -O1 "$CXX_QUIRK")

$CC $SAN_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX $SAN_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"

for t in $TARGETS; do
  $CXX $SAN_FLAGS $DEBUG_FLAGS "${HARNESS_FLAGS[@]}" "${HARNESS_INC[@]}" -c "$SRC/mayhem/$t.cc" -o "$B/$t.o"
  $CXX $SAN_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$t.o" "$B/lsan_off.o" \
    -Wl,--start-group "${LIBS[@]}" -Wl,--end-group "${SYS_LIBS[@]}" -o "$SRC/$t"
  $CXX $SAN_FLAGS $DEBUG_FLAGS "$B/$t.o" "$B/standalone_main.o" "$B/lsan_off.o" \
    -Wl,--start-group "${LIBS[@]}" -Wl,--end-group "${SYS_LIBS[@]}" -o "$SRC/$t-standalone"
done

# 3) Oracle build: normal flags, independent tree; test.sh only runs these.
TB="$SRC/mayhem/build-test"
fresh_if_compiler_changed "$TB"
cmake -S "$SRC" -B "$TB" "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS $CXX_QUIRK"
TEST_TARGETS="pdu_test mac_pdu_nr_test nas_5g_msg_test ngap_asn1_test s1ap_asn1_test rrc_asn1_test srsran_asn1_nas_test asn1_utils_test rlc_am_data_test rlc_am_control_test rlc_um_data_test rlc_am_nr_pdu_test rlc_um_nr_pdu_test rrc_asn1_decoder nas_decoder"
# shellcheck disable=SC2086
cmake --build "$TB" -j"$MAYHEM_JOBS" --target $TEST_TARGETS $LIB_TARGETS

TLIBS=()
for t in $LIB_TARGETS; do
  TLIBS+=("$(find "$TB/lib" -name "lib$t.a" | head -n1)")
done
$CXX -std=c++14 -O1 $COVERAGE_FLAGS "$CXX_QUIRK" -DBUILD_TYPE_RELEASE -I"$SRC/lib/include" -I"$TB/lib/include" \
  "$SRC/mayhem/kat.cc" -Wl,--start-group "${TLIBS[@]}" -Wl,--end-group "${SYS_LIBS[@]}" -o "$SRC/mayhem-kat"
