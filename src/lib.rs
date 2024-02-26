use std::slice;

use aes_gcm::{AeadInPlace, KeyInit};

const TAG_SIZE: u32 = 16;
const KEY_SIZE: u32 = 32;
const NONCE_SIZE: u32 = 12;

// AES GCM with 256bit key, 12byte nonce and 16byte tag/mac
type Cipher = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12, aes_gcm::aead::consts::U16>;

#[no_mangle]
pub extern "C" fn is_supported() -> u32 {
    return 1
}

#[no_mangle]
pub extern "C" fn aes_gcm_encrypt(
    key: *const u8, key_size: u32,
    nonce: *const u8, nonce_size: u32,
    data_ptr: *mut u8, data_in_size: u32, data_in_capacity: u32) -> u32 {
    if key_size != KEY_SIZE {
        eprintln!("Key has wrong size, expected {} bytes", KEY_SIZE);
        return 0;
    }
    if nonce_size != NONCE_SIZE {
        eprintln!("Nonce has wrong size, expected {} bytes", NONCE_SIZE);
        return 0;
    }
    if data_in_size + TAG_SIZE > data_in_capacity {
        eprintln!("Data buffer is not big enough, need at least {} bytes extra", TAG_SIZE);
        return 0;
    }
    let key: &[u8] = unsafe { slice::from_raw_parts(key, key_size as usize) };
    let nonce: &[u8] = unsafe { slice::from_raw_parts(nonce, nonce_size as usize) };
    let data: &mut [u8] = unsafe { slice::from_raw_parts_mut(data_ptr, data_in_size as usize) };
    let data_out_tag: &mut [u8] = unsafe { slice::from_raw_parts_mut(data_ptr.offset(data_in_size as isize), TAG_SIZE as usize) };

    let cipher = Cipher::new(key.into());

    let result = cipher.encrypt_in_place_detached(nonce.into(), b"", data);
    match result {
        Ok(tag) => {
            if tag.len() != TAG_SIZE as usize {
                eprintln!("Tag returned by encryption has wrong size, expected {} bytes, got {} bytes", TAG_SIZE, tag.len());
                return 0;
            }
            data_out_tag.copy_from_slice(tag.as_slice());
            return (data.len() + data_out_tag.len()) as u32;
        }
        Err(e) => {
            eprintln!("Failed to encrypt data: {e}");
            return 0;
        }
    }
}

#[no_mangle]
pub extern "C" fn aes_gcm_decrypt(
    key: *const u8, key_size: u32,
    nonce: *const u8, nonce_size: u32,
    data_ptr: *mut u8, data_in_size: u32) -> u32 {
    if key_size != KEY_SIZE {
        eprintln!("Key has wrong size, expected {} bytes", KEY_SIZE);
        return 0;
    }
    if nonce_size != NONCE_SIZE {
        eprintln!("Nonce has wrong size, expected {} bytes", NONCE_SIZE);
        return 0;
    }
    if data_in_size <= TAG_SIZE {
        eprintln!("Data buffer is not big enough, expected at least {} bytes (1 data byte + tag)", TAG_SIZE + 1);
        return 0;
    }
    let key: &[u8] = unsafe { slice::from_raw_parts(key, key_size as usize) };
    let nonce: &[u8] = unsafe { slice::from_raw_parts(nonce, nonce_size as usize) };
    let data_size = (data_in_size - TAG_SIZE) as usize;
    let data: &mut [u8] = unsafe { slice::from_raw_parts_mut(data_ptr, data_size) };
    let data_tag: &[u8] = unsafe { slice::from_raw_parts(data_ptr.offset(data_size as isize), TAG_SIZE as usize) };

    let cipher = Cipher::new(key.into());

    let result = cipher.decrypt_in_place_detached(nonce.into(), b"", data, data_tag.into());
    match result {
        Ok(()) => {
            return data_size as u32;
        }
        Err(e) => {
            eprintln!("Failed to decrypt data: {e}");
            return 0;
        }
    }
}
