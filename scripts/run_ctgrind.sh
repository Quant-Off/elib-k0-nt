#!/usr/bin/env bash
# ctgrind 실행 스크립트고 컨테이너 내부에서 실행됩니다.
#
# 1. ct_valgrind_probe 예제를 x86_64-unknown-linux-gnu로 빌드
# 2. Valgrind memcheck으로 실행
# 3. "Conditional jump or move depends on uninitialised value(s)" 또는
#    "Use of uninitialised value of size N" 출력이 있으면 CT 위반 보고
#
# 본 스크립트는 Linux x86_64 환경(또는 macOS/Apple Silicon 의 Docker
# linux/amd64 컨테이너) 안에서 실행되어야 합니다

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v valgrind >/dev/null 2>&1; then
    echo "FAIL: valgrind 미설치 (Dockerfile.ctgrind 컨테이너 사용 필요)" >&2
    exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "FAIL: ctgrind 는 x86_64 호스트가 필요!!!!! 현재 $(uname -m)" >&2
    echo "      Apple Silicon 등에서는 Dockerfile.ctgrind의 linux/amd64 컨테이너 사용" >&2
    exit 1
fi

TARGET="x86_64-unknown-linux-gnu"
# 컨테이너 안에서는 이미 CARGO_BUILD_TARGET 으로 설정됨

echo ">> Building ct_valgrind_probe ($TARGET, release)"
( cd constant-time && cargo build --release --example ct_valgrind_probe --target "${TARGET}" ) 1>&2

BIN="target/${TARGET}/release/examples/ct_valgrind_probe"
if [[ ! -x "${BIN}" ]]; then
    echo "FAIL: probe 바이너리 빌드 실패: ${BIN}" >&2
    exit 1
fi

LOG="$(mktemp)"
trap 'rm -f "${LOG}"' EXIT

echo ">> Valgrind 실행 (memcheck)"
# --track-origins=yes: uninit 의 원천 추적
# --error-exitcode=99: 위반 발견 시 비-제로 exit
# --tool=memcheck: 기본 (CT 검증에 적합)
set +e
valgrind \
    --tool=memcheck \
    --track-origins=yes \
    --error-exitcode=99 \
    --quiet \
    "${BIN}" >"${LOG}" 2>&1
vg_exit=$?
set -e

cat "${LOG}"

if [[ "${vg_exit}" -ne 0 ]]; then
    echo "RESULT: FAIL (Valgrind exit ${vg_exit} (CT 위반 또는 진단 실패))"
    exit 1
fi

echo ">> negative probe self-check: 의도적 leak 이 Valgrind 에 의해 잡히는지"
( cd constant-time && cargo build --release --example ct_valgrind_negative --target "${TARGET}" ) 1>&2
NEG_BIN="target/${TARGET}/release/examples/ct_valgrind_negative"
NEG_LOG="$(mktemp)"
trap 'rm -f "${LOG}" "${NEG_LOG}"' EXIT
set +e
valgrind \
    --tool=memcheck \
    --track-origins=yes \
    --error-exitcode=99 \
    --quiet \
    "${NEG_BIN}" >"${NEG_LOG}" 2>&1
neg_exit=$?
set -e

if [[ "${neg_exit}" -eq 0 ]]; then
    echo "    FAIL (negative probe가 PASS 처리됨 (검사기 자체 결함))"
    cat "${NEG_LOG}"
    exit 1
fi
if grep -qE "Conditional jump|uninitialised" "${NEG_LOG}"; then
    echo "    PASS (Valgrind가 negative probe 의 비밀 의존 분기를 정확히 보고)"
else
    echo "    FAIL (Valgrind exit ${neg_exit}이지만 분기/uninit 메시지 없음)"
    cat "${NEG_LOG}"
    exit 1
fi

echo "RESULT: PASS (Valgrind 검증 통과 + 검사기 self-check 정확성 확인)"
exit 0
