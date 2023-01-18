use crate::{Error, Result};

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256, Block,
};

type CipherTy = Aes256;
const KEY_SIZE: usize = 32;
const BLOCK_SIZE: usize = 16;

fn to_blocks(val: &str) -> Result<Vec<Block>> {
    use Error::*;

    if let Some(idx) = val.find('\0') {
        return Err(AppError(format!(
            "value contains a NUL character at byte index {}",
            idx
        )));
    }

    let val_bytes = val.len();
    let val_blocks = val_bytes / BLOCK_SIZE + if val_bytes % BLOCK_SIZE == 0 { 0 } else { 1 };

    let mut res = Vec::with_capacity(val_blocks);

    for block_idx in 0..val_blocks {
        let min_idx = block_idx * BLOCK_SIZE;
        let max_idx = std::cmp::min(min_idx + BLOCK_SIZE, val_bytes);
        let mut block = [0u8; BLOCK_SIZE];
        block[..max_idx - min_idx].copy_from_slice(&val.as_bytes()[min_idx..max_idx]);
        res.push(Block::from(block));
    }

    Ok(res)
}

fn from_blocks(blocks: Vec<Block>) -> Result<String> {
    use Error::*;

    let mut res = String::with_capacity(blocks.len() * BLOCK_SIZE);

    for block in blocks {
        let slice = block.as_slice();
        let first_nul = slice.iter().position(|e| *e == 0).unwrap_or(BLOCK_SIZE);
        res.push_str(
            std::str::from_utf8(&slice[..first_nul])
                .map_err(|_| AppError("UTF-8 decode error".to_owned()))?,
        );
    }

    Ok(res)
}

pub fn encrypt(master_pw: &str, val: &str) -> Result<Vec<u8>> {
    use Error::*;

    if master_pw.len() > KEY_SIZE {
        return Err(AuthError(format!(
            "master password must be <= {} bytes long",
            KEY_SIZE
        )));
    }

    let mut key = [0u8; KEY_SIZE];
    key[..master_pw.len()].copy_from_slice(master_pw.as_bytes());
    let key = GenericArray::from(key);
    let cipher = CipherTy::new(&key);

    let mut blocks = to_blocks(val)?;
    cipher.encrypt_blocks(&mut blocks[..]);

    let mut res = Vec::with_capacity(blocks.len());
    for block in blocks {
        res.extend_from_slice(block.as_slice());
    }

    Ok(res)
}

pub fn decrypt(master_pw: &str, bytes: &Vec<u8>) -> Result<String> {
    use Error::*;

    if master_pw.len() > KEY_SIZE {
        return Err(AuthError(format!(
            "master password must be <= {} bytes long",
            KEY_SIZE
        )));
    }

    if bytes.len() % BLOCK_SIZE != 0 {
        return Err(AppError(format!(
            "encoded bytes have size {}, which is not a multiple of the block size ({})",
            bytes.len(),
            BLOCK_SIZE
        )));
    }

    let mut key = [0u8; KEY_SIZE];
    key[..master_pw.len()].copy_from_slice(master_pw.as_bytes());
    let key = GenericArray::from(key);
    let cipher = CipherTy::new(&key);

    let num_blocks = bytes.len() / BLOCK_SIZE;
    let mut blocks = Vec::with_capacity(num_blocks);
    for block_idx in 0..num_blocks {
        let mut array = [0u8; BLOCK_SIZE];
        array.copy_from_slice(&bytes[BLOCK_SIZE * block_idx..BLOCK_SIZE * (block_idx + 1)]);
        blocks.push(Block::from(array));
    }

    cipher.decrypt_blocks(&mut blocks[..]);

    from_blocks(blocks)
}
