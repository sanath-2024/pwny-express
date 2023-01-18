use crate::{Error, Result};

pub fn authenticate(master_pw: &str, master_pw_hash: &str) -> Result<()> {
    use Error::*;

    let bcrypt_res = bcrypt::verify(master_pw, master_pw_hash).map_err(|e| {
        AuthError(format!(
            "failed to verify master password hash: {}",
            e.to_string()
        ))
    })?;

    if bcrypt_res {
        Ok(())
    } else {
        Err(AuthError("incorrect master password".to_owned()))
    }
}
