#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Oracle 1: srsRAN's own unit tests (built with normal flags by build.sh). A test passes when it exits 0
# AND prints at least the expected number of lines of its assertion trace, so a no-op/exit(0) stub fails.
TB="$SRC/mayhem/build-test"
passed=0; failed=0
run_unit() {
  local name="$1" min_lines="$2" bin out
  bin="$(find "$TB" -name "$name" -type f -perm -u+x 2>/dev/null | head -n1)"
  if [ -z "$bin" ]; then echo "FAIL $name: binary missing (build.sh bug)" >&2; failed=$((failed+1)); return; fi
  out="$(timeout 600 "$bin" 2>&1)"; local rc=$?
  local lines; lines="$(printf '%s\n' "$out" | grep -c .)"
  if [ "$rc" -eq 0 ] && [ "$lines" -ge "$min_lines" ]; then
    echo "PASS $name (lines=$lines)"; passed=$((passed+1))
  else
    echo "FAIL $name (rc=$rc lines=$lines, expected >= $min_lines)" >&2; failed=$((failed+1))
  fi
}
run_unit pdu_test 800
run_unit mac_pdu_nr_test 90
run_unit nas_5g_msg_test 45
run_unit ngap_asn1_test 70
run_unit s1ap_asn1_test 10
run_unit rrc_asn1_test 1
run_unit srsran_asn1_nas_test 4
run_unit asn1_utils_test 3
run_unit rlc_am_nr_pdu_test 55
run_unit rlc_um_nr_pdu_test 2
run_unit rlc_am_data_test 0
run_unit rlc_am_control_test 0
run_unit rlc_um_data_test 0

# Oracle 2: known-answer probe. mayhem-kat decodes fixed NGAP/S1AP/RRC/NAS/MAC-NR/RLC/GTP-U vectors and
# prints the decoded fields; every line is compared against the frozen golden output.
KAT="$SRC/mayhem-kat"
if [ ! -x "$KAT" ]; then
  echo "FAIL mayhem-kat missing (build.sh bug)" >&2
  failed=$((failed+1))
else
  kat_out="$(timeout 120 "$KAT" 2>&1)"; kat_rc=$?
  golden="$(cat <<'GOLDEN'
ngap.unpack=0
ngap.proc_code=21
ngap.gnb_id=1
ngap.plmn=0xf110
ngap.tac=0x75
ngap.consumed_bytes=52
s1ap.unpack=0
s1ap.proc_code=17
s1ap.enb_id=0x19b
s1ap.enb_name=enb0019b
rrc.unpack=0
rrc.is_setup=1
rrc.transaction_id=0
rrc.phys_cfg_ded_present=1
rrc.consumed_bytes=26
nas5g.unpack=0
nas5g.is_5gmm=1
nas5g.is_plain=1
nas5g.is_registration_request=1
nas5g.initial_registration=1
nas5g.follow_on_pending=1
nas5g.guti=1
nas5g.sec_cap_present=1
nas5g.ea1=1 ea4=0 ia3=1 ia4=0
epsnas.unpack=0
epsnas.cont_type=1
epsnas.cont_len=6
epsnas.add_info=0
macnr.unpack=0
macnr.subpdus=3
macnr.subpdu0=lcid:62,sdu_len:6,total_len:7
macnr.subpdu1=lcid:4,sdu_len:8,total_len:10
macnr.subpdu2=lcid:63,sdu_len:1,total_len:2
rlc.lte_data.sn=0x123
rlc.lte_data.p=1
rlc.lte_data.remaining=2
rlc.lte_status.ack_sn=10
rlc.lte_status.nacks=0
rlc.nr_status.ack_sn=10
rlc.nr_status.nacks=1
rlc.nr_status.nack0_sn=5
rlc.nr_data.header_len=2
rlc.nr_data.sn=0xab
rlc.nr_data.p=1
gtpu.read=1
gtpu.teid=0x1020304
gtpu.msg_type=0xff
gtpu.length=4
gtpu.payload_bytes=4
GOLDEN
)"
  if [ "$kat_rc" -ne 0 ]; then
    echo "FAIL mayhem-kat exited $kat_rc" >&2; failed=$((failed+1))
  fi
  while IFS= read -r want; do
    if printf '%s\n' "$kat_out" | grep -qxF -- "$want"; then
      passed=$((passed+1))
    else
      echo "FAIL kat: expected line not found: $want" >&2; failed=$((failed+1))
    fi
  done <<<"$golden"
  extra="$(diff <(printf '%s\n' "$kat_out") <(printf '%s\n' "$golden") | grep -c '^<' || true)"
  if [ "${extra:-0}" -ne 0 ]; then
    echo "FAIL kat: $extra unexpected output line(s)" >&2; failed=$((failed+1))
  fi
fi

emit_ctrf "srsran-4g-unit+kat" "$passed" "$failed" 0
