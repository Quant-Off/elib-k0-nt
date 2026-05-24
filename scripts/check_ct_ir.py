#!/usr/bin/env python3
"""LLVM IR 데이터 흐름 기반 상수-시간 검사기입니다.

LLVM IR(.ll) 파일에서 검사 대상 함수를 추출하고, 각 함수의 인자를
'비밀(tainted)'로 마킹한 뒤 forward taint propagation으로 SSA def-use
그래프 위에서 도달 가능한 모든 값을 계산합니다. 그 후 `br i1 <cond>` /
`switch <ty> <cond>` 명령의 condition operand 가 tainted 집합에 속하면
데이터 의존 분기(상수-시간 위반)로 보고합니다.

본 검사는 asm grep 보다 한 단계 위며, LLVM 백엔드 최적화 변동성에
무관하게 컴파일러 입력 직전 IR 에서 비밀 의존성을 잡습니다.

Tanit 모델:
    - 함수 인자 = 비밀 (보수적 가정)
    - 모든 SSA 명령: operand 중 하나라도 tainted면 결과도 tainted
    - phi: 모든 incoming이 tainted union
    - call/asm 결과: 인자 중 하나라도 tainted면 결과 tainted
    - 상수(i32 0, i64 8 등 immediate)는 not tainted
    - alloca 자체는 not tainted(stack slot 주소만)
    - br i1/switch의 condition 검사

알려진 한계:
    - inter-procedural 분석 없음 (호출된 함수 내부 미추적). leaf 함수에는
      충분하나, 큰 함수 그래프는 인-라인 보장이 필요
    - taint가 한 번 부여되면 영영 유지(constant-time bit mask 적용 후
      "탈비밀화" 패턴 미모델). 보수적 거짓 양성(false-positive) 가능
    - undef / poison 등 일부 LLVM 의미 미반영

사용:
    python3 scripts/check_ct_ir.py <ll-file> --func-prefix probe_
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path


_SSA_RE = re.compile(r"%[\w.][\w.\-]*")
_DEFINE_RE = re.compile(r"^define\b.*?@([\w$.]+)\s*\((.*)\)")
_ASSIGN_RE = re.compile(r"^\s*(%[\w.][\w.\-]*)\s*=\s*(.*)$")
_BR_COND_RE = re.compile(r"^\s*br\s+i1\s+(%[\w.][\w.\-]*)\s*,")
_SWITCH_RE = re.compile(
    r"^\s*switch\s+\w+\s+(%[\w.][\w.\-]*)\s*,"
)


def parse_args_list(arglist: str) -> list[str]:
    """LLVM define 의 ( … ) 안에서 SSA 인자명만 추출"""
    args = []
    depth = 0
    cur = ""
    for ch in arglist + ",":
        if ch in "<({[":
            depth += 1
            cur += ch
        elif ch in ">)}]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            tok = cur.strip()
            if tok:
                m = _SSA_RE.findall(tok)
                if m:
                    args.append(m[-1])
            cur = ""
        else:
            cur += ch
    return args


def extract_functions(ll: str) -> dict[str, list[str]]:
    """{name: [body lines including header]} 로 분리"""
    lines = ll.splitlines()
    funcs: dict[str, list[str]] = {}
    cur_name: str | None = None
    cur_body: list[str] = []
    depth = 0
    for line in lines:
        if cur_name is None:
            m = _DEFINE_RE.match(line)
            if m:
                cur_name = m.group(1)
                cur_body = [line]
                depth = line.count("{") - line.count("}")
                if depth == 0 and "{" in line:
                    funcs[cur_name] = cur_body
                    cur_name = None
        else:
            cur_body.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                funcs[cur_name] = cur_body
                cur_name = None
                cur_body = []
                depth = 0
    return funcs


def operands_of(rhs: str) -> set[str]:
    """RHS 텍스트에서 참조되는 SSA value 집합 (immediate/상수 제외)"""
    return set(_SSA_RE.findall(rhs))


def analyze_function(
    name: str,
    body: list[str],
    public_arg_indices: set[int] | None = None,
) -> list[tuple[int, str]]:
    """함수 한 개를 taint 분석. 위반 (line_idx, message) 목록 반환

    `public_arg_indices`에 명시된 인자 인덱스(0-base)는 비밀이 아닌
    공개 정보로 간주되어 taint source에서 제외됨. 예로: ct_eq_slice의
    slice length 인자(인덱스 1, 3)는 명세상 공개라 분기를 허용해도 됨
    """
    header = body[0]
    m = _DEFINE_RE.match(header)
    assert m, f"unexpected header for {name}: {header}"
    arg_ssas = parse_args_list(m.group(2))
    public_arg_indices = public_arg_indices or set()
    secret_args = [a for i, a in enumerate(arg_ssas) if i not in public_arg_indices]

    # SSA 정의 -> operand 집합
    defs: dict[str, set[str]] = {}
    cond_uses: list[tuple[int, str]] = []  # (line_idx, cond_ssa)

    for idx, line in enumerate(body):
        stripped = line.split(";", 1)[0]  # 라인 코멘트 제거
        if not stripped.strip():
            continue
        am = _ASSIGN_RE.match(stripped)
        if am:
            lhs, rhs = am.group(1), am.group(2)
            ops = operands_of(rhs)
            ops.discard(lhs)  # self-reference 방지
            defs[lhs] = ops
            continue
        bm = _BR_COND_RE.match(stripped)
        if bm:
            cond_uses.append((idx, bm.group(1)))
            continue
        sm = _SWITCH_RE.match(stripped)
        if sm:
            cond_uses.append((idx, sm.group(1)))
            continue

    # forward taint propagation: 비밀 인자 -> 모든 reachable def
    tainted: set[str] = set(secret_args)
    changed = True
    while changed:
        changed = False
        for lhs, ops in defs.items():
            if lhs in tainted:
                continue
            if ops & tainted:
                tainted.add(lhs)
                changed = True

    # br/switch 검사
    violations: list[tuple[int, str]] = []
    for idx, cond in cond_uses:
        if cond in tainted:
            origin = "function argument" if cond in secret_args else "transitive"
            violations.append(
                (idx, f"조건분기 condition {cond} 가 비밀 입력에 의존 ({origin})")
            )
    return violations


def main() -> int:
    ap = argparse.ArgumentParser(description="LLVM IR 상수-시간 검사기")
    ap.add_argument("ll_file", type=Path, help="검사할 .ll 파일")
    ap.add_argument(
        "--func-prefix",
        action="append",
        default=[],
        help="검사 대상 함수 prefix (반복 지정 가능, 예: --func-prefix probe_)",
    )
    ap.add_argument(
        "--func",
        action="append",
        default=[],
        help="검사할 단일 함수명 (정확 일치)",
    )
    ap.add_argument(
        "--public-arg-index",
        action="append",
        type=int,
        default=[],
        help="해당 인덱스의 인자를 공개로 마킹 (분기 허용). 반복 지정 가능",
    )
    args = ap.parse_args()
    public_indices = set(args.public_arg_index)

    if not args.func_prefix and not args.func:
        ap.error("--func-prefix 또는 --func 중 하나는 필수")

    ll = args.ll_file.read_text()
    funcs = extract_functions(ll)

    targets = []
    for name in funcs:
        if name in args.func or any(name.startswith(p) for p in args.func_prefix):
            targets.append(name)

    if not targets:
        print(f"FAIL: 검사 대상 함수를 찾지 못함 (.ll: {args.ll_file})", file=sys.stderr)
        return 1

    fail = 0
    for name in sorted(targets):
        violations = analyze_function(name, funcs[name], public_indices)
        if not violations:
            print(f"    PASS {name}")
        else:
            print(f"    FAIL {name}")
            for line_idx, msg in violations:
                src = funcs[name][line_idx].rstrip()
                print(f"        L{line_idx + 1}: {src}")
                print(f"            -> {msg}")
            fail = 1

    if fail:
        print("RESULT: FAIL (비밀 의존 분기 검출)")
        return 1
    print(f"RESULT: PASS ({len(targets)} 함수가 비밀 의존 분기 없음)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
