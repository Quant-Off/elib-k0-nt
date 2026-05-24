use core::mem::MaybeUninit;
use zeroize::{Secret, Zeroize, zeroize_flat};

#[cfg_attr(miri, ignore)]
#[test]
fn secret_array_zeroized_on_drop() {
    let mut storage: MaybeUninit<Secret<[u8; 32]>> = MaybeUninit::uninit();
    unsafe {
        storage.write(Secret::new([0xA5u8; 32]));
        let ptr = storage.assume_init_ref().expose().as_ptr();
        let byte_len = core::mem::size_of::<[u8; 32]>();

        let pre = core::slice::from_raw_parts(ptr, byte_len);
        assert!(
            pre.iter().any(|&b| b != 0),
            "Secret<[u8;32]> 가 비어 있음 — 테스트 전제 위반"
        );

        storage.assume_init_drop();

        let post = core::slice::from_raw_parts(ptr, byte_len);
        assert!(
            post.iter().all(|&b| b == 0),
            "Secret<[u8;32]> 가 Drop 후 소거되지 않음"
        );
    }
}

// into_inner 은 소비된 self 의 inner 슬롯을 byte volatile-0 으로 덮어쓴 뒤
// mem::forget 하고 복사본을 반환한다. 소비된 self 슬롯은 함수 프레임 내부이고
// move-out 이후 회수되므로 외부에서 주소-readback 으로 관측할 수 없다(소거 동일
// byte-루프는 Drop / zeroize_flat 테스트가 이미 readback 으로 커버).
// 따라서 본 테스트는 into_inner 의 외부-관측 가능한 계약 — 추출 값 정확성과
// Drop 우회(double-free 없이 정상 반환) — 을 검증한다.
#[cfg_attr(miri, ignore)]
#[test]
fn secret_into_inner_extracts_value() {
    let extracted = Secret::new([0x3Cu8; 32]).into_inner();
    assert!(
        extracted.iter().all(|&b| b == 0x3C),
        "into_inner 반환값이 원본 비밀과 다름 — 추출 실패"
    );

    let words = Secret::new([0xABCD_1234u32; 8]).into_inner();
    assert!(
        words.iter().all(|&w| w == 0xABCD_1234),
        "into_inner 반환값이 원본 비밀과 다름 — u32 배열 추출 실패"
    );
}

#[cfg_attr(miri, ignore)]
#[test]
fn zeroize_flat_wipes_bytes() {
    #[repr(C)]
    struct Blob {
        a: u64,
        b: [u8; 16],
        c: u32,
    }

    let mut storage: MaybeUninit<Blob> = MaybeUninit::uninit();
    unsafe {
        storage.write(Blob {
            a: 0xDEAD_BEEF_DEAD_BEEF,
            b: [0x77u8; 16],
            c: 0xCAFE_BABE,
        });
        let ptr = storage.as_ptr() as *const u8;
        let byte_len = core::mem::size_of::<Blob>();

        let pre = core::slice::from_raw_parts(ptr, byte_len);
        assert!(
            pre.iter().any(|&b| b != 0),
            "Blob 가 비어 있음 — 테스트 전제 위반"
        );

        zeroize_flat(storage.assume_init_mut());

        let post = core::slice::from_raw_parts(ptr, byte_len);
        assert!(
            post.iter().all(|&b| b == 0),
            "zeroize_flat 후 메모리가 소거되지 않음"
        );
    }
}

#[cfg_attr(miri, ignore)]
#[test]
fn array_zeroize_wipes() {
    let mut bytes = [0x5Au8; 64];
    bytes.zeroize();
    assert!(
        bytes.iter().all(|&b| b == 0),
        "[u8; 64]::zeroize 후 소거되지 않음"
    );

    let mut words = [0xFFFF_FFFF_FFFF_FFFFu64; 16];
    words.zeroize();
    assert!(
        words.iter().all(|&w| w == 0),
        "[u64; 16]::zeroize 후 소거되지 않음"
    );
}

#[cfg_attr(miri, ignore)]
#[test]
fn slice_zeroize_wipes() {
    let mut backing = [0x9Bu8; 48];
    let mut view: &mut [u8] = &mut backing;
    view.zeroize();
    assert!(
        backing.iter().all(|&b| b == 0),
        "&mut [u8]::zeroize 후 소거되지 않음"
    );
}
