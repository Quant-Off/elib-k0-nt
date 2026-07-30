#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]

use rng::{
    HashDRBGSHA3_224, HashDRBGSHA3_256, HashDRBGSHA3_384, HashDRBGSHA3_512, HashDRBGSHA224,
    HashDRBGSHA256, HashDRBGSHA384, HashDRBGSHA512,
};
use sha2::{SHA2, SHA224, SHA256, SHA384, SHA512};
use sha3::{SHA3, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alg {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

const ALL_ALGS: [Alg; 8] = [
    Alg::SHA224,
    Alg::SHA256,
    Alg::SHA384,
    Alg::SHA512,
    Alg::SHA3_224,
    Alg::SHA3_256,
    Alg::SHA3_384,
    Alg::SHA3_512,
];

impl Alg {
    fn label(self) -> &'static str {
        match self {
            Alg::SHA224 => "SHA-224",
            Alg::SHA256 => "SHA-256",
            Alg::SHA384 => "SHA-384",
            Alg::SHA512 => "SHA-512",
            Alg::SHA3_224 => "SHA3-224",
            Alg::SHA3_256 => "SHA3-256",
            Alg::SHA3_384 => "SHA3-384",
            Alg::SHA3_512 => "SHA3-512",
        }
    }

    fn seed_len(self) -> usize {
        match self {
            Alg::SHA224 | Alg::SHA3_224 | Alg::SHA256 | Alg::SHA3_256 => 55,
            Alg::SHA384 | Alg::SHA3_384 | Alg::SHA512 | Alg::SHA3_512 => 111,
        }
    }

    fn min_entropy(self) -> usize {
        match self {
            Alg::SHA224 | Alg::SHA3_224 => 14,
            Alg::SHA256 | Alg::SHA3_256 => 16,
            Alg::SHA384 | Alg::SHA3_384 => 24,
            Alg::SHA512 | Alg::SHA3_512 => 32,
        }
    }

    fn hash_fn(self) -> HashFn {
        match self {
            Alg::SHA224 => one_shot_sha2::<SHA224>,
            Alg::SHA256 => one_shot_sha2::<SHA256>,
            Alg::SHA384 => one_shot_sha2::<SHA384>,
            Alg::SHA512 => one_shot_sha2::<SHA512>,
            Alg::SHA3_224 => one_shot_sha3::<SHA3_224>,
            Alg::SHA3_256 => one_shot_sha3::<SHA3_256>,
            Alg::SHA3_384 => one_shot_sha3::<SHA3_384>,
            Alg::SHA3_512 => one_shot_sha3::<SHA3_512>,
        }
    }

    fn run(self, case: &Case, out_len: usize) -> Vec<u8> {
        match self {
            Alg::SHA224 => run_case::<HashDRBGSHA224>(case, out_len),
            Alg::SHA256 => run_case::<HashDRBGSHA256>(case, out_len),
            Alg::SHA384 => run_case::<HashDRBGSHA384>(case, out_len),
            Alg::SHA512 => run_case::<HashDRBGSHA512>(case, out_len),
            Alg::SHA3_224 => run_case::<HashDRBGSHA3_224>(case, out_len),
            Alg::SHA3_256 => run_case::<HashDRBGSHA3_256>(case, out_len),
            Alg::SHA3_384 => run_case::<HashDRBGSHA3_384>(case, out_len),
            Alg::SHA3_512 => run_case::<HashDRBGSHA3_512>(case, out_len),
        }
    }
}

fn one_shot_sha2<H: SHA2>(msg: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(msg);
    hasher.finalize().as_bytes().to_vec()
}

fn one_shot_sha3<H: SHA3>(msg: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(msg);
    hasher.finalize().as_bytes().to_vec()
}

type HashFn = fn(&[u8]) -> Vec<u8>;

fn opt(bytes: &[u8]) -> Option<&[u8]> {
    (!bytes.is_empty()).then_some(bytes)
}

//
// 라이브러리 경로 (rng 크레이트의 Hash_DRBG)
//

trait DrbgOps: Sized {
    fn kat_instantiate(entropy: &[u8], nonce: &[u8], ps: Option<&[u8]>) -> Self;
    fn kat_reseed(&mut self, entropy: &[u8], ai: Option<&[u8]>);
    fn kat_generate(&mut self, out: &mut [u8], ai: Option<&[u8]>);
}

macro_rules! impl_drbg_ops {
    ($($t:ty),+) => {$(
        impl DrbgOps for $t {
            fn kat_instantiate(entropy: &[u8], nonce: &[u8], ps: Option<&[u8]>) -> Self {
                unsafe { <$t>::new_from_entropy(entropy, nonce, ps) }
                    .expect("KAT instantiate 실패")
            }
            fn kat_reseed(&mut self, entropy: &[u8], ai: Option<&[u8]>) {
                <$t>::reseed(self, entropy, ai).expect("KAT reseed 실패");
            }
            fn kat_generate(&mut self, out: &mut [u8], ai: Option<&[u8]>) {
                <$t>::generate(self, out, ai).expect("KAT generate 실패");
            }
        }
    )+};
}

impl_drbg_ops!(
    HashDRBGSHA224,
    HashDRBGSHA256,
    HashDRBGSHA384,
    HashDRBGSHA512,
    HashDRBGSHA3_224,
    HashDRBGSHA3_256,
    HashDRBGSHA3_384,
    HashDRBGSHA3_512
);

struct Case {
    entropy: Vec<u8>,
    nonce: Vec<u8>,
    ps: Vec<u8>,
    flow: Flow,
}

enum Flow {
    NoPr {
        reseed_entropy: Vec<u8>,
        reseed_ai: Vec<u8>,
        ai: [Vec<u8>; 2],
    },
    UsePr {
        pr: [(Vec<u8>, Vec<u8>); 2],
    },
}

fn run_case<T: DrbgOps>(case: &Case, out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    let mut drbg = T::kat_instantiate(&case.entropy, &case.nonce, opt(&case.ps));
    match &case.flow {
        Flow::NoPr {
            reseed_entropy,
            reseed_ai,
            ai,
        } => {
            drbg.kat_reseed(reseed_entropy, opt(reseed_ai));
            drbg.kat_generate(&mut out, opt(&ai[0]));
            drbg.kat_generate(&mut out, opt(&ai[1]));
        }
        Flow::UsePr { pr } => {
            for (entropy, ai) in pr {
                drbg.kat_reseed(entropy, opt(ai));
                drbg.kat_generate(&mut out, None);
            }
        }
    }
    out
}

//
// 독립 참조 구현 (자가 검증 차분용 — rng 크레이트 코드와 공유 없음)
//

struct RefDrbg {
    hash: HashFn,
    seed_len: usize,
    v: Vec<u8>,
    c: Vec<u8>,
    reseed_counter: u64,
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn be_add(dst: &mut [u8], src: &[u8]) {
    let mut carry = 0u16;
    let mut src_iter = src.iter().rev();
    for d in dst.iter_mut().rev() {
        let s = u16::from(src_iter.next().copied().unwrap_or(0));
        let sum = u16::from(*d) + s + carry;
        *d = sum as u8;
        carry = sum >> 8;
    }
}

fn ref_hash_df(hash: HashFn, parts: &[&[u8]], out_bytes: usize) -> Vec<u8> {
    let bits_be = ((out_bytes as u32) * 8).to_be_bytes();
    let body = concat(parts);
    let mut out = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_bytes {
        out.extend_from_slice(&hash(&concat(&[&[counter], &bits_be, &body])));
        counter += 1;
    }
    out.truncate(out_bytes);
    out
}

impl RefDrbg {
    fn instantiate(alg: Alg, entropy: &[u8], nonce: &[u8], ps: Option<&[u8]>) -> Self {
        let hash = alg.hash_fn();
        let seed_len = alg.seed_len();
        let seed = concat(&[entropy, nonce, ps.unwrap_or(&[])]);
        let v = ref_hash_df(hash, &[&seed], seed_len);
        let c = ref_hash_df(hash, &[&[0x00], &v], seed_len);
        RefDrbg {
            hash,
            seed_len,
            v,
            c,
            reseed_counter: 1,
        }
    }

    fn reseed(&mut self, entropy: &[u8], ai: Option<&[u8]>) {
        let new_v = ref_hash_df(
            self.hash,
            &[&[0x01], &self.v, entropy, ai.unwrap_or(&[])],
            self.seed_len,
        );
        self.v = new_v;
        self.c = ref_hash_df(self.hash, &[&[0x00], &self.v], self.seed_len);
        self.reseed_counter = 1;
    }

    fn generate(&mut self, out_len: usize, ai: Option<&[u8]>) -> Vec<u8> {
        if let Some(ai) = ai {
            let w = (self.hash)(&concat(&[&[0x02], &self.v, ai]));
            be_add(&mut self.v, &w);
        }
        let mut data = self.v.clone();
        let mut out = Vec::new();
        while out.len() < out_len {
            out.extend_from_slice(&(self.hash)(&data));
            be_add(&mut data, &[1]);
        }
        out.truncate(out_len);
        let h = (self.hash)(&concat(&[&[0x03], &self.v]));
        be_add(&mut self.v, &h);
        let c = self.c.clone();
        be_add(&mut self.v, &c);
        be_add(&mut self.v, &self.reseed_counter.to_be_bytes());
        self.reseed_counter += 1;
        out
    }
}

fn run_case_ref(alg: Alg, case: &Case, out_len: usize) -> Vec<u8> {
    let mut drbg = RefDrbg::instantiate(alg, &case.entropy, &case.nonce, opt(&case.ps));
    match &case.flow {
        Flow::NoPr {
            reseed_entropy,
            reseed_ai,
            ai,
        } => {
            drbg.reseed(reseed_entropy, opt(reseed_ai));
            drbg.generate(out_len, opt(&ai[0]));
            drbg.generate(out_len, opt(&ai[1]))
        }
        Flow::UsePr { pr } => {
            let mut out = Vec::new();
            for (entropy, ai) in pr {
                drbg.reseed(entropy, opt(ai));
                out = drbg.generate(out_len, None);
            }
            out
        }
    }
}

//
// req / sam / rsp 파싱과 대조
//

fn hex_decode(s: &str, ctx: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "{ctx}: 홀수 길이 16진 문자열");
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16);
            let lo = char::from(pair[1]).to_digit(16);
            match (hi, lo) {
                (Some(hi), Some(lo)) => ((hi << 4) | lo) as u8,
                _ => panic!("{ctx}: 16진수가 아닌 문자"),
            }
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(
            char::from_digit(u32::from(b >> 4), 16)
                .unwrap()
                .to_ascii_uppercase(),
        );
        out.push(
            char::from_digit(u32::from(b & 0x0F), 16)
                .unwrap()
                .to_ascii_uppercase(),
        );
    }
    out
}

struct Section {
    header: Vec<String>,
    blocks: Vec<Vec<(String, String)>>,
}

fn parse_sections(content: &str, ctx: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut block: Option<Vec<(String, String)>> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(pending) = block.take() {
                sections
                    .last_mut()
                    .unwrap_or_else(|| panic!("{ctx}: 헤더 없이 블록 등장"))
                    .blocks
                    .push(pending);
            }
        } else if trimmed.starts_with('[') {
            assert!(block.is_none(), "{ctx}: 헤더 라인이 블록 내부에 등장");
            match sections.last_mut() {
                Some(last) if last.blocks.is_empty() => last.header.push(trimmed.to_string()),
                _ => sections.push(Section {
                    header: vec![trimmed.to_string()],
                    blocks: Vec::new(),
                }),
            }
        } else {
            let (name, value) = trimmed
                .split_once('=')
                .unwrap_or_else(|| panic!("{ctx}: 잘못된 필드 형식 {line:?}"));
            assert!(!sections.is_empty(), "{ctx}: 헤더 없이 필드 등장");
            block
                .get_or_insert_default()
                .push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    if let Some(pending) = block.take() {
        sections
            .last_mut()
            .unwrap_or_else(|| panic!("{ctx}: 헤더 없이 블록 등장"))
            .blocks
            .push(pending);
    }
    sections
}

fn header_value<'a>(header: &'a [String], name: &str) -> Option<&'a str> {
    header.iter().find_map(|line| {
        let inner = line.strip_prefix('[')?.strip_suffix(']')?;
        let (key, value) = inner.split_once('=')?;
        (key.trim() == name).then_some(value.trim())
    })
}

struct Header {
    lines: Vec<String>,
    entropy_len: usize,
    nonce_len: usize,
    ps_len: usize,
    ai_len: usize,
    out_len: usize,
}

fn header_byte_len(header: &[String], name: &str, ctx: &str) -> usize {
    let bits: usize = header_value(header, name)
        .unwrap_or_else(|| panic!("{ctx}: 헤더 {name} 누락"))
        .parse()
        .unwrap_or_else(|_| panic!("{ctx}: 헤더 {name} 파싱 실패"));
    assert!(
        bits.is_multiple_of(8),
        "{ctx}: {name} {bits}이 8의 배수가 아님"
    );
    bits / 8
}

fn parse_header(section: &Section, alg: Alg, pr: bool, ctx: &str) -> Header {
    assert!(
        section.header.first().map(String::as_str) == Some(&format!("[{}]", alg.label())[..]),
        "{ctx}: 헤더 알고리즘이 파일명 {}과 다름",
        alg.label()
    );
    let pr_value = header_value(&section.header, "PredictionResistance")
        .unwrap_or_else(|| panic!("{ctx}: PredictionResistance 헤더 누락"));
    let header_pr = match pr_value {
        "True" => true,
        "False" => false,
        other => panic!("{ctx}: PredictionResistance 값 {other:?} 해석 불가"),
    };
    assert!(header_pr == pr, "{ctx}: PR 헤더가 파일명과 다름");
    let header = Header {
        lines: section.header.clone(),
        entropy_len: header_byte_len(&section.header, "EntropyInputLen", ctx),
        nonce_len: header_byte_len(&section.header, "NonceLen", ctx),
        ps_len: header_byte_len(&section.header, "PersonalizationStringLen", ctx),
        ai_len: header_byte_len(&section.header, "AdditionalInputLen", ctx),
        out_len: header_byte_len(&section.header, "ReturnedBitsLen", ctx),
    };
    assert!(
        header.entropy_len >= alg.min_entropy(),
        "{ctx}: EntropyInputLen 이 최소 엔트로피 미달"
    );
    header
}

const NO_PR_FIELDS: [&str; 8] = [
    "COUNT",
    "EntropyInput",
    "Nonce",
    "PersonalizationString",
    "EntropyInputReseed",
    "AdditionalInputReseed",
    "AdditionalInput",
    "AdditionalInput",
];

const USE_PR_FIELDS: [&str; 8] = [
    "COUNT",
    "EntropyInput",
    "Nonce",
    "PersonalizationString",
    "EntropyInputPR",
    "AdditionalInput",
    "EntropyInputPR",
    "AdditionalInput",
];

fn checked_hex(value: &str, expected_len: usize, ctx: &str) -> Vec<u8> {
    let bytes = hex_decode(value, ctx);
    assert!(
        bytes.len() == expected_len,
        "{ctx}: 길이 {}바이트가 헤더 기대 {expected_len}바이트와 다름",
        bytes.len()
    );
    bytes
}

fn parse_case(block: &[(String, String)], pr: bool, header: &Header, ctx: &str) -> Case {
    let expected_names: &[&str] = if pr { &USE_PR_FIELDS } else { &NO_PR_FIELDS };
    assert!(
        block.len() == expected_names.len(),
        "{ctx}: 필드 수 {} (기대 {})",
        block.len(),
        expected_names.len()
    );
    for ((name, _), expected) in block.iter().zip(expected_names) {
        assert!(name == expected, "{ctx}: 필드 {name:?} (기대 {expected:?})");
    }
    let value = |idx: usize| block[idx].1.as_str();
    let entropy = checked_hex(value(1), header.entropy_len, &format!("{ctx} EntropyInput"));
    let nonce = checked_hex(value(2), header.nonce_len, &format!("{ctx} Nonce"));
    let ps = checked_hex(
        value(3),
        header.ps_len,
        &format!("{ctx} PersonalizationString"),
    );
    let flow = if pr {
        Flow::UsePr {
            pr: [
                (
                    checked_hex(
                        value(4),
                        header.entropy_len,
                        &format!("{ctx} EntropyInputPR 1"),
                    ),
                    checked_hex(value(5), header.ai_len, &format!("{ctx} AdditionalInput 1")),
                ),
                (
                    checked_hex(
                        value(6),
                        header.entropy_len,
                        &format!("{ctx} EntropyInputPR 2"),
                    ),
                    checked_hex(value(7), header.ai_len, &format!("{ctx} AdditionalInput 2")),
                ),
            ],
        }
    } else {
        Flow::NoPr {
            reseed_entropy: checked_hex(
                value(4),
                header.entropy_len,
                &format!("{ctx} EntropyInputReseed"),
            ),
            reseed_ai: checked_hex(
                value(5),
                header.ai_len,
                &format!("{ctx} AdditionalInputReseed"),
            ),
            ai: [
                checked_hex(value(6), header.ai_len, &format!("{ctx} AdditionalInput 1")),
                checked_hex(value(7), header.ai_len, &format!("{ctx} AdditionalInput 2")),
            ],
        }
    };
    Case {
        entropy,
        nonce,
        ps,
        flow,
    }
}

type FieldRow = Vec<(String, String)>;

struct ExpSection {
    header: Header,
    rows: Vec<FieldRow>,
}

fn expected_sections(alg: Alg, pr: bool, sections: &[Section], ctx: &str) -> Vec<ExpSection> {
    assert!(!sections.is_empty(), "{ctx}: 섹션 없음");
    sections
        .iter()
        .enumerate()
        .map(|(sec_idx, section)| {
            let sctx = format!("{ctx} 섹션 {sec_idx}");
            let header = parse_header(section, alg, pr, &sctx);
            assert!(!section.blocks.is_empty(), "{sctx}: COUNT 블록 없음");
            let rows = section
                .blocks
                .iter()
                .enumerate()
                .map(|(idx, block)| {
                    let bctx = format!("{sctx} 블록 {idx}");
                    let case = parse_case(block, pr, &header, &bctx);
                    assert!(
                        block[0].1 == idx.to_string(),
                        "{bctx}: COUNT {} (기대 {idx})",
                        block[0].1
                    );
                    let returned = alg.run(&case, header.out_len);
                    let mut row = block.clone();
                    row.push(("ReturnedBits".to_string(), hex_encode(&returned)));
                    row
                })
                .collect();
            ExpSection { header, rows }
        })
        .collect()
}

fn total_blocks(expected: &[ExpSection]) -> usize {
    expected.iter().map(|s| s.rows.len()).sum()
}

fn compare_sections(expected: &[ExpSection], parsed: &[Section], ctx: &str) -> Vec<String> {
    assert!(
        parsed.len() == expected.len(),
        "{ctx}: 기대 {}섹션 vs 파일 {}섹션",
        expected.len(),
        parsed.len()
    );
    let mut mismatches = Vec::new();
    for (sec_idx, (exp, section)) in expected.iter().zip(parsed.iter()).enumerate() {
        assert!(
            section.header == exp.header.lines,
            "{ctx} 섹션 {sec_idx}: 헤더가 req 와 다름"
        );
        assert!(
            section.blocks.len() == exp.rows.len(),
            "{ctx} 섹션 {sec_idx}: 기대 {}블록 vs 파일 {}블록",
            exp.rows.len(),
            section.blocks.len()
        );
        for (idx, (exp_fields, blk)) in exp.rows.iter().zip(section.blocks.iter()).enumerate() {
            assert!(
                blk.len() == exp_fields.len(),
                "{ctx} 섹션 {sec_idx} 블록 {idx}: 필드 수 {} (기대 {})",
                blk.len(),
                exp_fields.len()
            );
            for ((name, value), (exp_name, exp_value)) in blk.iter().zip(exp_fields.iter()) {
                assert!(
                    name == exp_name,
                    "{ctx} 섹션 {sec_idx} 블록 {idx}: 필드 {name:?} (기대 {exp_name:?})"
                );
                if !value.eq_ignore_ascii_case(exp_value) {
                    mismatches.push(format!(
                        "섹션 {sec_idx} 블록 {idx} {name}: 계산 {exp_value} vs 파일 {value}"
                    ));
                }
            }
        }
    }
    mismatches
}

fn fill_template(template: &str, expected: &[ExpSection], ctx: &str) -> String {
    let newline = if template.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out: Vec<String> = Vec::new();
    let mut sec_idx = 0usize;
    let mut header_idx = 0usize;
    let mut block_idx = 0usize;
    let mut field_idx = 0usize;
    let mut saw_field = false;
    for line in template.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if saw_field {
                block_idx += 1;
                field_idx = 0;
                saw_field = false;
            }
            out.push(line.to_string());
            continue;
        }
        if trimmed.starts_with('[') {
            assert!(sec_idx < expected.len(), "{ctx}: 템플릿 섹션 수 초과");
            if header_idx == expected[sec_idx].header.lines.len() {
                assert!(
                    block_idx == expected[sec_idx].rows.len() && !saw_field,
                    "{ctx} 섹션 {sec_idx}: 블록 수 {block_idx} (기대 {}) 상태에서 다음 섹션 시작",
                    expected[sec_idx].rows.len()
                );
                sec_idx += 1;
                header_idx = 0;
                block_idx = 0;
                field_idx = 0;
                assert!(sec_idx < expected.len(), "{ctx}: 템플릿 섹션 수 초과");
            }
            let exp_lines = &expected[sec_idx].header.lines;
            assert!(
                header_idx < exp_lines.len() && trimmed == exp_lines[header_idx],
                "{ctx} 섹션 {sec_idx}: 템플릿 헤더 {trimmed:?} 이 req 헤더와 다름"
            );
            header_idx += 1;
            out.push(line.to_string());
            continue;
        }
        saw_field = true;
        let (name, value) = trimmed
            .split_once('=')
            .unwrap_or_else(|| panic!("{ctx}: 잘못된 템플릿 라인 {line:?}"));
        let name = name.trim();
        let value = value.trim();
        assert!(
            sec_idx < expected.len() && block_idx < expected[sec_idx].rows.len(),
            "{ctx}: 템플릿 블록 수가 기대 초과 (섹션 {sec_idx} 블록 {block_idx})"
        );
        let row = &expected[sec_idx].rows[block_idx];
        assert!(
            field_idx < row.len(),
            "{ctx} 섹션 {sec_idx} 블록 {block_idx}: 템플릿 필드 수가 기대 {}필드 초과",
            row.len()
        );
        let (exp_name, exp_value) = &row[field_idx];
        field_idx += 1;
        assert!(
            name == exp_name,
            "{ctx} 섹션 {sec_idx} 블록 {block_idx}: 템플릿 필드 {name:?} (기대 {exp_name:?})"
        );
        if value == "?" {
            out.push(format!("{name} = {exp_value}"));
        } else {
            assert!(
                value.eq_ignore_ascii_case(exp_value),
                "{ctx} 섹션 {sec_idx} 블록 {block_idx}: 템플릿 {name} 값이 req 계산과 불일치"
            );
            out.push(line.to_string());
        }
    }
    assert!(
        sec_idx == expected.len() - 1
            && header_idx == expected[sec_idx].header.lines.len()
            && block_idx + usize::from(saw_field) == expected[sec_idx].rows.len(),
        "{ctx}: 템플릿이 req 보다 짧음 (섹션 {sec_idx} 블록 {block_idx})"
    );
    let mut rsp = out.join(newline);
    if template.ends_with('\n') {
        rsp.push_str(newline);
    }
    rsp
}

fn synthesize(expected: &[ExpSection], newline: &str) -> String {
    let mut out = String::new();
    for (sec_idx, section) in expected.iter().enumerate() {
        if sec_idx > 0 {
            out.push_str(newline);
        }
        for line in &section.header.lines {
            out.push_str(line);
            out.push_str(newline);
        }
        for fields in &section.rows {
            out.push_str(newline);
            for (name, value) in fields {
                out.push_str(&format!("{name} = {value}{newline}"));
            }
        }
    }
    out
}

//
// 파일 수집
//

fn classify(path: &Path) -> Option<(Alg, bool)> {
    let stem = path.file_stem()?.to_str()?.to_ascii_uppercase();
    if !stem.starts_with("HASH_DRBG") {
        return None;
    }
    let pr = if stem.contains("(USE PR)") {
        true
    } else if stem.contains("(NO PR)") {
        false
    } else {
        return None;
    };
    let alg = if stem.contains("SHA3-224") {
        Alg::SHA3_224
    } else if stem.contains("SHA3-256") {
        Alg::SHA3_256
    } else if stem.contains("SHA3-384") {
        Alg::SHA3_384
    } else if stem.contains("SHA3-512") {
        Alg::SHA3_512
    } else if stem.contains("SHA-224") {
        Alg::SHA224
    } else if stem.contains("SHA-256") {
        Alg::SHA256
    } else if stem.contains("SHA-384") {
        Alg::SHA384
    } else if stem.contains("SHA-512") {
        Alg::SHA512
    } else {
        return None;
    };
    Some((alg, pr))
}

fn cavp_root() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KCMVP_CAVP_DIR") {
        return Some(PathBuf::from(dir));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.join("cavp");
    root.is_dir().then_some(root)
}

fn collect_req_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_req_files(&path, found);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("req"))
            && classify(&path).is_some()
        {
            found.push(path);
        }
    }
}

fn report_mismatches(path: &Path, mismatches: &[String], total: usize, failures: &mut Vec<String>) {
    eprintln!(
        "{} 대조 실패 {}건 (전체 {total} 블록)",
        path.display(),
        mismatches.len()
    );
    for m in mismatches.iter().take(10) {
        eprintln!("  {m}");
    }
    failures.push(format!("{}: {}건 불일치", path.display(), mismatches.len()));
}

// cavp/ 트리의 Hash_DRBG no PR·use PR req 16종(파일당 4섹션 × 15 COUNT)을 계산해 rsp 파일로 출력합니다 (sam 은 배포 템플릿 그대로 두고 레이아웃·대조 기준으로만 사용, 기존 rsp 는 회귀 대조)
#[test]
fn kcmvp_hash_drbg_req_vs_rsp() {
    let Some(root) = cavp_root() else {
        eprintln!("cavp 디렉터리 없음 - KCMVP Hash_DRBG 대조 생략");
        return;
    };
    let mut req_files = Vec::new();
    collect_req_files(&root, &mut req_files);
    req_files.sort();
    if req_files.is_empty() {
        eprintln!(
            "{}: Hash_DRBG req 파일 없음 - KCMVP Hash_DRBG 대조 생략",
            root.display()
        );
        return;
    }

    let mut failures = Vec::new();
    for req in &req_files {
        let ctx = req.display().to_string();
        let (alg, pr) = classify(req).unwrap();
        let content = fs::read_to_string(req).unwrap_or_else(|e| panic!("{ctx}: 읽기 실패 {e}"));
        let sections = parse_sections(&content, &ctx);
        let expected = expected_sections(alg, pr, &sections, &ctx);
        let total = total_blocks(&expected);
        let sam_path = req.with_extension("sam");
        let rsp_path = req.with_extension("rsp");

        let mut layout = None;
        let mut sam_ok = true;
        match fs::read_to_string(&sam_path) {
            Ok(sam) if sam.contains("= ?") => layout = Some(sam),
            Ok(sam) => {
                let sam_sections = parse_sections(&sam, &ctx);
                let mismatches = compare_sections(&expected, &sam_sections, &ctx);
                if mismatches.is_empty() {
                    println!("{} 대조 통과 ({total} 블록)", sam_path.display());
                    layout = Some(sam);
                } else {
                    report_mismatches(&sam_path, &mismatches, total, &mut failures);
                    sam_ok = false;
                }
            }
            Err(_) => {}
        }
        if !sam_ok {
            continue;
        }

        match fs::read_to_string(&rsp_path) {
            Ok(rsp) if !rsp.contains("= ?") => {
                let rsp_sections = parse_sections(&rsp, &ctx);
                let mismatches = compare_sections(&expected, &rsp_sections, &ctx);
                if mismatches.is_empty() {
                    println!("{} 대조 통과 ({total} 블록)", rsp_path.display());
                } else {
                    report_mismatches(&rsp_path, &mismatches, total, &mut failures);
                }
            }
            _ => {
                let rsp = match &layout {
                    Some(template) => fill_template(template, &expected, &ctx),
                    None => {
                        let newline = if content.contains("\r\n") {
                            "\r\n"
                        } else {
                            "\n"
                        };
                        synthesize(&expected, newline)
                    }
                };
                fs::write(&rsp_path, rsp).unwrap_or_else(|e| panic!("{ctx}: rsp 쓰기 실패 {e}"));
                println!("{} 생성 ({total} 블록)", rsp_path.display());
            }
        }
    }
    assert!(
        failures.is_empty(),
        "rsp·sam 대조 실패\n{}",
        failures.join("\n")
    );
}

// SP 800-90A 를 그대로 옮긴 독립 참조 구현과의 전수 차분(8 알고리즘 × PR × ps·ai 유무)으로 라이브러리 경로와 하네스 흐름을 자가 검증하고, 템플릿 채움·오염 검출 로직을 점검합니다
#[test]
fn kcmvp_hash_drbg_self_check() {
    for (alg_idx, alg) in ALL_ALGS.into_iter().enumerate() {
        for pr in [false, true] {
            for with_ps in [false, true] {
                for with_ai in [false, true] {
                    let seed_byte = 0x11 + (alg_idx as u8) * 0x10;
                    let entropy = vec![seed_byte; alg.min_entropy().max(24)];
                    let nonce = vec![seed_byte ^ 0xFF; 16];
                    let ps = if with_ps {
                        vec![0xA5u8; 20]
                    } else {
                        Vec::new()
                    };
                    let ai_body = if with_ai {
                        vec![0x3Cu8; 16]
                    } else {
                        Vec::new()
                    };
                    let flow = if pr {
                        Flow::UsePr {
                            pr: [
                                (vec![0xB0 ^ seed_byte; entropy.len()], ai_body.clone()),
                                (vec![0xC1 ^ seed_byte; entropy.len()], ai_body.clone()),
                            ],
                        }
                    } else {
                        Flow::NoPr {
                            reseed_entropy: vec![0xD2 ^ seed_byte; entropy.len()],
                            reseed_ai: ai_body.clone(),
                            ai: [ai_body.clone(), ai_body.clone()],
                        }
                    };
                    let case = Case {
                        entropy,
                        nonce,
                        ps,
                        flow,
                    };
                    let out_len = 100;
                    let lib = alg.run(&case, out_len);
                    let reference = run_case_ref(alg, &case, out_len);
                    assert!(
                        lib == reference,
                        "{} pr={pr} ps={with_ps} ai={with_ai}: 라이브러리·참조 구현 차분 불일치",
                        alg.label()
                    );
                    assert!(lib.iter().any(|&b| b != 0), "{} 출력이 전부 0", alg.label());
                }
            }
        }
    }

    let header = Header {
        lines: vec![
            "[SHA-256]".to_string(),
            "[PredictionResistance = False]".to_string(),
        ],
        entropy_len: 32,
        nonce_len: 16,
        ps_len: 0,
        ai_len: 0,
        out_len: 32,
    };
    let entropy_hex = "11".repeat(32);
    let nonce_hex = "22".repeat(16);
    let reseed_hex = "33".repeat(32);
    let case = Case {
        entropy: hex_decode(&entropy_hex, "self"),
        nonce: hex_decode(&nonce_hex, "self"),
        ps: Vec::new(),
        flow: Flow::NoPr {
            reseed_entropy: hex_decode(&reseed_hex, "self"),
            reseed_ai: Vec::new(),
            ai: [Vec::new(), Vec::new()],
        },
    };
    let returned = hex_encode(&Alg::SHA256.run(&case, header.out_len));
    let rows: Vec<FieldRow> = vec![vec![
        ("COUNT".to_string(), "0".to_string()),
        ("EntropyInput".to_string(), entropy_hex.clone()),
        ("Nonce".to_string(), nonce_hex.clone()),
        ("PersonalizationString".to_string(), String::new()),
        ("EntropyInputReseed".to_string(), reseed_hex.clone()),
        ("AdditionalInputReseed".to_string(), String::new()),
        ("AdditionalInput".to_string(), String::new()),
        ("AdditionalInput".to_string(), String::new()),
        ("ReturnedBits".to_string(), returned.clone()),
    ]];
    let expected = vec![ExpSection { header, rows }];
    let template = format!(
        "[SHA-256]\r\n[PredictionResistance = False]\r\n\r\nCOUNT = 0\r\nEntropyInput = {entropy_hex}\r\nNonce = {nonce_hex}\r\nPersonalizationString = \r\nEntropyInputReseed = {reseed_hex}\r\nAdditionalInputReseed = \r\nAdditionalInput = \r\nAdditionalInput = \r\nReturnedBits = ?\r\n"
    );
    let filled = fill_template(&template, &expected, "self-fill");
    assert!(!filled.contains('?'), "템플릿 미기입 잔존");
    let filled_sections = parse_sections(&filled, "self-verify");
    let mismatches = compare_sections(&expected, &filled_sections, "self-verify");
    assert!(mismatches.is_empty(), "생성 rsp 대조 실패 {mismatches:?}");

    let corrupted_char = if returned.ends_with('0') { "1" } else { "0" };
    let corrupted_hex = format!("{}{corrupted_char}", &returned[..returned.len() - 1]);
    let corrupted = filled.replacen(returned.as_str(), &corrupted_hex, 1);
    let corrupted_sections = parse_sections(&corrupted, "self-corrupt");
    let mismatches = compare_sections(&expected, &corrupted_sections, "self-corrupt");
    assert!(mismatches.len() == 1, "오염 rsp 미검출 {mismatches:?}");

    let synthesized = synthesize(&expected, "\r\n");
    let synthesized_sections = parse_sections(&synthesized, "self-synth");
    let mismatches = compare_sections(&expected, &synthesized_sections, "self-synth");
    assert!(mismatches.is_empty(), "합성 rsp 대조 실패 {mismatches:?}");
}
