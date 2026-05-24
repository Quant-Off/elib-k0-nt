//! BLAKE의 위협적 입력에 대한 회귀 방어 테스트 모듈입니다.
//!
//! 본 슈트는 두 목적을 동시에 달성합니다.
//!
//! 1. 위협 입력 (경계 길이 / 비대칭 길이 / OOB-trigger 시도 / 패딩 경계
//!    bit-flip / max output 등) 에서 panic / UB / wrong-result 가 없는지
//!    결정론적으로 검증.
//! 2. MIRI 친화: inline asm 미지원 경로에서도 동일 결과를 재현하여
//!    UB 회귀 가드 역할 수행.

use blake::{Blake2b, Blake3, MAX_OUTPUT_LEN, SecureBuffer, blake2b_long, ct_eq_slice};
use constant_time::CtEqOps;

//
// ct_eq_slice: 길이 경계와 비대칭 입력 회귀
//

#[test]
fn threat_ct_eq_slice_zero_length() {
    // 길이 0 두 슬라이스는 동등 (vacuous truth + 길이 일치)
    assert_eq!(ct_eq_slice(&[], &[]).unwrap_u8(), 1);
}

#[test]
fn threat_ct_eq_slice_one_empty() {
    // 한 쪽만 비어있는 경우는 길이 불일치 → 0
    assert_eq!(ct_eq_slice(&[], &[1, 2, 3]).unwrap_u8(), 0);
    assert_eq!(ct_eq_slice(&[1, 2, 3], &[]).unwrap_u8(), 0);
}

#[test]
fn threat_ct_eq_slice_prefix_match_then_diverge() {
    // 짧은 쪽이 긴 쪽의 prefix 일치: 길이 불일치로 인해 결과 0
    // (단순 prefix 매치를 진정한 equality로 오인하지 않는지)
    let a: [u8; 4] = [1, 2, 3, 4];
    let b: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(ct_eq_slice(&a, &b).unwrap_u8(), 0);
}

#[test]
fn threat_ct_eq_slice_single_byte_flip() {
    // 1024 바이트 중 1 비트만 flip -> 0 (어떤 위치든)
    let a = [0xA5u8; 1024];
    for pos in [0, 1, 256, 511, 512, 1022, 1023] {
        let mut b = a;
        b[pos] ^= 0x01;
        assert_eq!(ct_eq_slice(&a, &b).unwrap_u8(), 0, "pos={pos}");
    }
}

#[test]
fn threat_ct_eq_slice_max_output_len() {
    // MAX_OUTPUT_LEN (1024) byte 단위로 양극단 패턴 비교
    let zeros = [0u8; MAX_OUTPUT_LEN];
    let ones = [0xFFu8; MAX_OUTPUT_LEN];
    assert_eq!(ct_eq_slice(&zeros, &zeros).unwrap_u8(), 1);
    assert_eq!(ct_eq_slice(&ones, &ones).unwrap_u8(), 1);
    assert_eq!(ct_eq_slice(&zeros, &ones).unwrap_u8(), 0);
}

//
// SecureBuffer: 위협 인자 (할당 한계 / 0 / 1 / MAX_OUTPUT_LEN+1)
//

#[test]
fn threat_secure_buffer_zero_len() {
    // 길이 0 은 panic 없이 허용 (빈 버퍼)
    let buf = SecureBuffer::new_owned(0).expect("zero-length 허용");
    assert_eq!(buf.as_slice().len(), 0);
}

#[test]
fn threat_secure_buffer_at_max_len() {
    // 정확히 MAX_OUTPUT_LEN 은 허용
    let mut buf = SecureBuffer::new_owned(MAX_OUTPUT_LEN).unwrap();
    assert_eq!(buf.as_mut_slice().len(), MAX_OUTPUT_LEN);
}

#[test]
fn threat_secure_buffer_over_max_len() {
    // MAX_OUTPUT_LEN+1 은 panic 없이 AllocationFailed 반환
    let err = SecureBuffer::new_owned(MAX_OUTPUT_LEN + 1);
    assert!(err.is_err(), "초과 길이는 Err 이어야 함");
}

#[test]
fn threat_secure_buffer_usize_max() {
    // usize::MAX 같은 극단 입력도 panic 없이 Err
    let err = SecureBuffer::new_owned(usize::MAX);
    assert!(err.is_err(), "usize::MAX 는 Err 이어야 함");
}

#[test]
fn threat_secure_buffer_ct_eq_different_lengths() {
    // 길이가 다른 SecureBuffer 비교는 즉시 0 (panic 없음)
    let mut a = SecureBuffer::new_owned(8).unwrap();
    let mut b = SecureBuffer::new_owned(16).unwrap();
    a.as_mut_slice().copy_from_slice(&[1; 8]);
    b.as_mut_slice().copy_from_slice(&[1; 16]);
    assert_eq!(CtEqOps::eq(&a, &b).unwrap_u8(), 0);
}

//
// Blake2b: 위협 입력
//

#[test]
fn threat_blake2b_empty_input_all_hash_lens() {
    // hash_len 경계 (1, 32, 64) 에 대해 panic 없이 정상 finalize
    for len in [1usize, 16, 32, 48, 64] {
        let h = Blake2b::new(len);
        let digest = h.finalize().expect("finalize panic");
        assert_eq!(digest.as_slice().len(), len);
    }
}

#[test]
fn threat_blake2b_exact_block_boundary() {
    // 128 byte (한 블록), 256 byte (두 블록), 129 byte (블록 + 1) 처리
    for len in [128usize, 129, 256, 1024] {
        let mut h = Blake2b::new(32);
        h.update(&vec![0xA5u8; len]);
        let d = h.finalize().expect("blockboundary panic");
        assert_eq!(d.as_slice().len(), 32);
    }
}

#[test]
fn threat_blake2b_many_small_updates() {
    // 1-byte 단위로 1000 회 update 누적 카운터 / 부분 블록 처리 회귀
    let mut h = Blake2b::new(32);
    for _ in 0..1000 {
        h.update(&[0xA5u8]);
    }
    let d = h.finalize().expect("small-update panic");
    // 1000 byte 입력의 결정론적 hash
    let mut h2 = Blake2b::new(32);
    h2.update(&vec![0xA5u8; 1000]);
    let d2 = h2.finalize().unwrap();
    assert_eq!(d.as_slice(), d2.as_slice(), "분할 update 가 비-등가");
}

#[test]
fn threat_blake2b_long_zero_len_err() {
    assert!(blake2b_long(b"x", 0).is_err(), "out_len=0 은 Err");
}

#[test]
fn threat_blake2b_long_at_block_boundaries() {
    // 64 (단일 BLAKE2b 경계), 65 (체이닝 시작), 1024 (Argon2id 최대) 모두 panic 없이 정확한 길이
    for len in [1usize, 64, 65, 80, 256, 1024] {
        let out = blake2b_long(b"threat-input", len).expect("blake2b_long panic");
        assert_eq!(out.as_slice().len(), len);
    }
}

#[test]
fn threat_blake2b_long_over_max() {
    // MAX_OUTPUT_LEN 초과는 panic 없이 AllocationFailed 반환
    assert!(blake2b_long(b"x", MAX_OUTPUT_LEN + 1).is_err());
}

//
// Blake3: 위협 입력
//

#[test]
fn threat_blake3_empty_keyed() {
    // empty input + key 는 표준상 정의된 동작 (panic 없이 32 byte digest)
    let key = [0u8; 32];
    let h = Blake3::new_keyed(&key);
    let d = h.finalize().expect("blake3 keyed empty panic");
    assert_eq!(d.as_slice().len(), 32);
}

#[test]
fn threat_blake3_chunk_boundary_inputs() {
    // CHUNK_LEN=1024 경계 ± 1 입력
    for len in [1023usize, 1024, 1025, 2047, 2048, 2049] {
        let mut h = Blake3::new();
        h.update(&vec![0x5Au8; len]);
        let d = h.finalize().expect("blake3 chunkboundary panic");
        assert_eq!(d.as_slice().len(), 32);
    }
}

#[test]
fn threat_blake3_xof_variable_lengths() {
    // XOF 출력 1 byte ~ 1024 byte 까지 panic 없이 정확한 길이
    for len in [1usize, 31, 32, 33, 64, 128, 1024] {
        let mut h = Blake3::new();
        h.update(b"xof-threat-input");
        let d = h.finalize_xof(len).expect("xof panic");
        assert_eq!(d.as_slice().len(), len);
    }
}

#[test]
fn threat_blake3_xof_over_max() {
    let mut h = Blake3::new();
    h.update(b"x");
    assert!(h.finalize_xof(MAX_OUTPUT_LEN + 1).is_err());
}

#[test]
fn threat_blake3_streaming_equivalence() {
    // 분할 update 의 결과가 일괄 update 와 byte-identical
    let input = [0xC3u8; 5000];
    let mut h_one = Blake3::new();
    h_one.update(&input);
    let d_one = h_one.finalize().unwrap();

    let mut h_split = Blake3::new();
    for chunk in input.chunks(7) {
        h_split.update(chunk);
    }
    let d_split = h_split.finalize().unwrap();
    assert_eq!(d_one.as_slice(), d_split.as_slice(), "streaming 회귀");
}

#[test]
fn threat_blake3_keyed_distinct_from_unkeyed() {
    // 동일 입력이지만 keyed/unkeyed가 서로 다른 digest를 생성하는지
    let input = b"distinct-domain-input";
    let mut hu = Blake3::new();
    hu.update(input);
    let du = hu.finalize().unwrap();

    let key = [0xA5u8; 32];
    let mut hk = Blake3::new_keyed(&key);
    hk.update(input);
    let dk = hk.finalize().unwrap();

    assert_ne!(
        du.as_slice(),
        dk.as_slice(),
        "keyed/unkeyed 가 동일 digest 도메인 분리 실패"
    );
}
