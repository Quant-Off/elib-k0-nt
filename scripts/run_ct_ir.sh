#!/usr/bin/env bash
# LLVM IR taint-based 상수시간 검증 일괄 실행

set -euo pipefail

cd "$(dirname "$0")/.."

HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
TARGET_DIR="target/${HOST}/release"

echo ">> 호스트 타깃: ${HOST}"

# 1) probe + negative_probe IR 빌드
( cd constant-time && cargo rustc --release --example ct_asm_probes --target "${HOST}" -- --emit=llvm-ir ) 1>&2
( cd constant-time && cargo rustc --release --example ct_negative_probe --target "${HOST}" -- --emit=llvm-ir ) 1>&2
# 2) blake lib IR 빌드
( cd blake && cargo rustc --release --lib --target "${HOST}" -- --emit=llvm-ir ) 1>&2

PROBE_LL=$(ls "${TARGET_DIR}/examples/ct_asm_probes-"*.ll | head -1)
NEG_LL=$(ls "${TARGET_DIR}/examples/ct_negative_probe-"*.ll | head -1)
BLAKE_LL=$(ls "${TARGET_DIR}/deps/blake-"*.ll | head -1)

fail=0

echo ">> CT probe (조건분기 / switch 부재)"
if ! python3 scripts/check_ct_ir.py "${PROBE_LL}" --func-prefix probe_; then
    fail=1
fi

echo ">> blake::ct_eq_slice (길이 공개 가정: 인덱스 1, 3)"
BLAKE_SYM=$(grep -oE '@_ZN5blake11ct_eq_slice[^(]+' "${BLAKE_LL}" | head -1 | sed 's/^@//')
if ! python3 scripts/check_ct_ir.py "${BLAKE_LL}" --func "${BLAKE_SYM}" \
        --public-arg-index 1 --public-arg-index 3; then
    fail=1
fi

echo ">> negative probe self-check (검사기 자체 정확성 검증)"
# negative probe 는 의도적으로 비밀 의존 분기 보유 -> 검사기가 FAIL을 내야 self-check PASS
# python3 exit 1 + pipefail 조합이 if 평가를 오염시키므로 출력을 변수로 캡쳐
neg_out=$(python3 scripts/check_ct_ir.py "${NEG_LL}" --func-prefix negative_ 2>&1 || true)
if echo "${neg_out}" | grep -q "^RESULT: FAIL"; then
    echo "    PASS (negative probe 가 정확히 FAIL 보고됨)"
else
    echo "    FAIL (negative probe 가 PASS 처리됨 (검사기 결함))"
    fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
    echo "RESULT: FAIL (IR-level 상수시간 위반 발견)"
    exit 1
fi
echo "RESULT: PASS (모든 검증 대상이 IR-level 상수시간 보장)"
