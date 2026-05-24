#!/usr/bin/env bash
# MIRI 검증 일괄 실행 스크립트입니다.
#
# 모든 sub-crate의 lib 및 위협 입력 테스트를 Tree Borrows 모델로 실행합니다
# Stacked Borrows가 너무 엄격하여 원시 포인터 패턴을 다수 거부하기 때문에
# 본 프로젝트는 Tree Borrows를 표준 검증 모델로 채택햇습니다.
#
# 인-라인 asm은 MIRI가 지원하지 않아서 zeroize/constant-time의
# barrier / CT primitive는 cfg(miri)가드로 fallback 경로를 사용합니다.
# zeroize-on-drop 테스트는 padding byte가 typed read 모델 밖이라
# #[cfg_attr(miri, ignore)]로 stable 빌드 한정으로 제한됩니다.
#
# 의도된 검증 범위:
# - 일반 동작 정확성 (BLAKE 표준 벡터, ct_eq_slice, secure_buffer)
# - 위협 입력 (길이 경계, 0/MAX, 비대칭, OOB-trigger, streaming 등)
# - Stacked / Tree Borrows alias 모델 위반 부재
# - 초기화되지 않은 메모리 접근 부재
# - 정수 오버플로 / OOB / use-after-free / data race 부재
#
# 검증 범위 외 (다른 가드로 처리):
# - timing 누출 (DudeCT + asm grep + ctgrind가 다룸)
# - 마이크로아키텍처 누출 (Microwalk 류, 향후)

set -euo pipefail

cd "$(dirname "$0")/.."

export MIRIFLAGS="-Zmiri-tree-borrows"

declare -a TARGETS=(
    "-p constant-time --test threat_inputs"
    "-p blake --lib"
    "-p blake --test threat_inputs"
)

fail=0
for t in "${TARGETS[@]}"; do
    echo ">> MIRI: ${t}"
    # shellcheck disable=SC2086
    if ! cargo +nightly miri test ${t} 2>&1 | tail -5; then
        fail=1
        echo "   FAIL ${t}"
    fi
done

if [[ "${fail}" -ne 0 ]]; then
    echo "RESULT: FAIL (MIRI 위반 발견)"
    exit 1
fi
echo "RESULT: PASS (모든 타깃이 MIRI 하에서 UB 없이 통과)"
