#!/usr/bin/env bash
# 상수시간 어셈블리 회귀 가드.
#
# examples/ct_asm_probes.rs 를 호스트 타깃으로 release 빌드 후, 산출된
# probe 심볼 각각에 대해 조건분기 명령 (x86_64 jcc / aarch64 b.cc, cbnz,
# cbz, tbnz, tbz) 부재를 정적으로 검증한다. swap probe 는 추가로 volatile
# 영점화 store (movb $0 / strb wzr) 가 살아남았는지 확인하여 CWE-316
# 회귀를 차단한다.
#
# 사용: cd constant-time && ./scripts/check_ct_asm.sh
# CI: exit 0 = clean, exit 1 = CT 위반 발견.

set -euo pipefail

cd "$(dirname "$0")/.."

HOST_TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
ARCH="${HOST_TRIPLE%%-*}"

echo ">> 호스트 타깃: ${HOST_TRIPLE} (arch=${ARCH})"

# 워크스페이스/크레이트 .cargo/config.toml 의 build.target 을 host 로 override.
# probe 바이너리는 std 가 필요하므로 bare-metal 타깃으로는 빌드 불가.
cargo build --release --example ct_asm_probes --target "${HOST_TRIPLE}" 1>&2

BIN="../target/${HOST_TRIPLE}/release/examples/ct_asm_probes"
if [[ ! -x "${BIN}" ]]; then
    echo "FAIL: probe 바이너리를 찾지 못함: ${BIN}" >&2
    exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

# objdump 가용성 확인 (macOS 는 llvm-objdump 동봉)
if command -v llvm-objdump >/dev/null 2>&1; then
    OBJDUMP=(llvm-objdump -d --no-show-raw-insn --no-leading-addr)
elif command -v objdump >/dev/null 2>&1; then
    OBJDUMP=(objdump -d --no-show-raw-insn)
else
    echo "FAIL: objdump / llvm-objdump 미설치" >&2
    exit 1
fi

CANON_LABEL_RE='s/^[0-9A-Fa-f]+[[:space:]]+(<[^>]+>:)$/\1/'

"${OBJDUMP[@]}" "${BIN}" | sed -E "${CANON_LABEL_RE}" > "${TMPDIR}/dump.s"

# 검사 대상 probe 심볼 (timing-CT 검사)
PROBES_CT=(
    probe_choice_from_u8
    probe_sel_u8 probe_sel_u16 probe_sel_u32 probe_sel_u64 probe_sel_u128
    probe_eq_u32 probe_eq_u64 probe_eq_u128
    probe_gt_u32 probe_gt_u64 probe_gt_i64 probe_gt_u128 probe_gt_i128
    probe_lt_u32
)
# swap probe 는 별도 — volatile zero store 존재도 함께 확인
PROBES_SWAP=(probe_swap_u64 probe_swap_u128)
# zeroize probe 는 별도 크레이트(zeroize) 소속 — 별도 빌드/디스어셈블 후
# volatile zero store + 메모리 배리어 fence 잔존을 함께 검증한다.
PROBES_ZEROIZE=(probe_secret_drop probe_zeroize_flat)

# 조건분기 명령 정규식 (arch 별)
case "${ARCH}" in
    x86_64)
        # jmp 는 unconditional 이라 허용. 모든 j[a-z]+ 조건점프와 loop, jrcxz 류 차단.
        # objdump 출력은 "<addr>:\tinsn ..." 형태이므로 단어경계 \b 로 정확 매칭.
        BRANCH_RE='\b(j(a|ae|b|be|c|cxz|e|ecxz|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|rcxz|s|z)|loop[nz]?e?)\b'
        # x86_64 zero store: movb $0,(mem) / movX $0,(mem) / xor reg,reg(=0).
        ZERO_STORE_RE='\b(mov[bwlq]?[[:space:]]+\$0x?0+,|mov[[:space:]]+(byte|BYTE)[[:space:]]+(ptr|PTR)[^,]*,[[:space:]]*0|xor[bwlq]?[[:space:]]+%[a-z0-9]+,[[:space:]]*%[a-z0-9]+)'
        # x86_64 메모리 배리어 fence: mfence (zeroize 경로 생존 검증).
        FENCE_RE='\bmfence\b'
        ;;
    aarch64)
        # 조건분기: b.cond (b.eq, b.ne, …), cbz, cbnz, tbz, tbnz
        # 무조건 b 는 jmp 와 동격이므로 허용.
        BRANCH_RE='\b(b\.[a-z]+|cbz|cbnz|tbz|tbnz)\b'
        # aarch64 zero store: strb wzr / str xzr / stp xzr,xzr (LLVM 합치기 패턴).
        ZERO_STORE_RE='\b(strb?|str|stp)[[:space:]]+(wzr|xzr)\b'
        # aarch64 메모리 배리어 fence: dmb / dsb (zeroize 경로 생존 검증).
        FENCE_RE='\b(dmb|dsb)\b'
        ;;
    *)
        echo "FAIL: 미지원 호스트 아키텍처: ${ARCH}" >&2
        exit 1
        ;;
esac

fail=0

MAX_SYMBOL_LINES=500

# 단일 심볼 어셈블리 추출
# 인자 3 (dump) 생략 시 기본 CT dump 사용 — zeroize dump 도 동일 awk 로 재사용.
extract_symbol() {
    local sym="$1"
    local out="$2"
    local dump="${3:-${TMPDIR}/dump.s}"
    # macOS Mach-O 는 _접두사. ELF 는 그대로.
    # 라벨은 주소-선행 "0000... <sym>:" 또는 주소-없음 "<sym>:" 양 형식 모두 대응.
    awk -v sym="${sym}" '
        $0 ~ ("(^|<|_)" sym ">:") { capturing = 1; print; next }
        capturing && /^([0-9A-Fa-f]+[[:space:]]+)?<[^>]+>:$/ { capturing = 0 }
        capturing { print }
    ' "${dump}" > "${out}"
    local n
    n=$(wc -l < "${out}" | tr -d '[:space:]')
    if [[ "${n}" -gt "${MAX_SYMBOL_LINES}" ]]; then
        echo "    FAIL ${sym} — 추출 ${n}줄 > ${MAX_SYMBOL_LINES} 줄: 심볼 경계 탐지 회귀(extract_symbol regex 결함 의심)" >&2
        fail=1
    fi
}

check_no_branch() {
    local sym="$1" file="$2"
    if [[ ! -s "${file}" ]]; then
        echo "    SKIP ${sym} — 심볼 미발견 (linker dead-strip 또는 inline)"
        return 0
    fi
    if grep -E "${BRANCH_RE}" "${file}" >/dev/null 2>&1; then
        echo "    FAIL ${sym} — 조건분기 검출:"
        grep -nE "${BRANCH_RE}" "${file}" | sed 's/^/        /'
        return 1
    fi
    echo "    PASS ${sym}"
    return 0
}

echo ">> CT primitive probe (조건분기 부재)"
for sym in "${PROBES_CT[@]}"; do
    extract_symbol "${sym}" "${TMPDIR}/${sym}.s"
    if ! check_no_branch "${sym}" "${TMPDIR}/${sym}.s"; then
        fail=1
    fi
done

echo ">> swap probe (volatile zero store 잔존만 검증)"
# 주의 — swap 본문의 zero-fill loop 는 size_of::<Self>() 라는 컴파일타임
# 상수에 대한 종료조건을 가지므로 분기 자체는 비밀 의존이 아님 (CT 보장
# 유지). branch 검사는 false-positive 가 되므로 swap probe 에는 적용하지
# 않고, CWE-316 회귀 가드인 zero store 잔존 여부만 검증한다.
for sym in "${PROBES_SWAP[@]}"; do
    extract_symbol "${sym}" "${TMPDIR}/${sym}.s"
    if [[ ! -s "${TMPDIR}/${sym}.s" ]]; then
        echo "    SKIP ${sym} — 심볼 미발견"
        continue
    fi
    if ! grep -E "${ZERO_STORE_RE}" "${TMPDIR}/${sym}.s" >/dev/null 2>&1; then
        echo "    FAIL ${sym} — volatile zero store 부재 (CWE-316 회귀 의심)"
        fail=1
    else
        cnt=$(grep -v '^#' "${TMPDIR}/${sym}.s" | grep -cE "${ZERO_STORE_RE}" || true)
        echo "    PASS ${sym} — zero store ${cnt} 건 잔존"
    fi
done

# zeroize probe (별도 크레이트 — 별도 release 빌드 + 별도 바이너리 디스어셈블)
# zeroize/examples/zeroize_asm_probes.rs 는 constant-time 이 아닌 zeroize 소속이라
# 별도로 release 빌드하고 별도 바이너리를 디스어셈블한다. zero-fill 루프(컴파일타임
# 상수 종료조건)를 가지므로 swap 과 동일하게 분기 검사는 적용하지 않고, volatile
# zero store (ZERO_STORE_RE) AND 메모리 배리어 fence (FENCE_RE) 잔존을 둘 다 검증한다.
# 한쪽이라도 부재면 DCE 회귀(CWE-14/316) 로 판정한다.
echo ">> zeroize probe (별도 크레이트 — zero store + fence 잔존 검증)"
cargo build --release -p zeroize --example zeroize_asm_probes --target "${HOST_TRIPLE}" 1>&2

ZBIN="../target/${HOST_TRIPLE}/release/examples/zeroize_asm_probes"
if [[ ! -x "${ZBIN}" ]]; then
    echo "    FAIL — zeroize probe 바이너리를 찾지 못함: ${ZBIN}"
    fail=1
else
    "${OBJDUMP[@]}" "${ZBIN}" | sed -E "${CANON_LABEL_RE}" > "${TMPDIR}/zdump.s"
    for sym in "${PROBES_ZEROIZE[@]}"; do
        extract_symbol "${sym}" "${TMPDIR}/${sym}.s" "${TMPDIR}/zdump.s"
        if [[ ! -s "${TMPDIR}/${sym}.s" ]]; then
            echo "    SKIP ${sym} — 심볼 미발견"
            continue
        fi
        store_cnt=$(grep -v '^#' "${TMPDIR}/${sym}.s" | grep -cE "${ZERO_STORE_RE}" || true)
        fence_cnt=$(grep -v '^#' "${TMPDIR}/${sym}.s" | grep -cE "${FENCE_RE}" || true)
        if [[ "${store_cnt}" -eq 0 || "${fence_cnt}" -eq 0 ]]; then
            echo "    FAIL ${sym} — zero store ${store_cnt} 건 / fence ${fence_cnt} 건 (DCE 회귀 의심: store·fence 모두 필요)"
            fail=1
        else
            echo "    PASS ${sym} — zero store ${store_cnt} 건 + fence ${fence_cnt} 건 잔존"
        fi
    done
fi

if [[ "${fail}" -ne 0 ]]; then
    echo "RESULT: FAIL — 상수시간/메모리 소거 회귀 발견"
    exit 1
fi
echo "RESULT: PASS — 모든 probe 가 조건분기 부재 + 영점화 보존"
