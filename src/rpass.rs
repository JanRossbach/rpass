use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use gpgme::{Context, Key, KeyListMode, Protocol};
use thiserror::Error;

const GPG_PROTOCOL: Protocol = Protocol::OpenPgp;
const GPG_ID_FILE_NAME: &str = "/.gpg-id";

pub struct RpassManager {
    pub store_dir: PathBuf,
    pub key: Key,
    context: Context,
    pub git_enabled: bool,
}

#[derive(Debug, Error)]
pub enum RpassManagerError {
    #[error("Could not find key")]
    KeyNotFound(io::Error),
    #[error("Could not create gpg context")]
    GpgContext(gpgme::Error),
    #[error("Could not encrypt password")]
    GpgEncrypt(gpgme::Error),
    #[error("Could not decrypt password")]
    GpgDecrypt(gpgme::Error),
    #[error("Could not create password file")]
    PasswordFile(io::Error),
    #[error("Could not open password file")]
    PasswordOpen(io::Error),
    #[error("Could not read store directory")]
    StoreDir(io::Error),
    #[error("Could not get secret keys")]
    SecretKeys(gpgme::Error),
    #[error("Could not set key list mode")]
    KeyListMode(gpgme::Error),
    #[error("Could not read directory entry")]
    DirEntry(io::Error),
}

impl RpassManager {
    pub fn new(store_dir: PathBuf) -> Result<RpassManager, RpassManagerError> {
        let gpg_id = read_gpg_id(&store_dir)?;
        let key = get_user_key(&gpg_id)?.ok_or(RpassManagerError::KeyNotFound(
            io::Error::new(io::ErrorKind::NotFound, "Could not find key"),
        ))?;
        let context = Context::from_protocol(GPG_PROTOCOL)
            .map_err(RpassManagerError::GpgContext)?;
        let git_enabled = is_git_dir(&store_dir);
        Ok(RpassManager {
            store_dir,
            key,
            context,
            git_enabled,
        })
    }

    pub fn change_key(&self, new_gpg_id: &str) -> Result<RpassManager, RpassManagerError> {
        let key = get_user_key(new_gpg_id)?.ok_or(RpassManagerError::KeyNotFound(
            io::Error::new(io::ErrorKind::NotFound, "Could not find key"),
        ))?;
        let context = Context::from_protocol(GPG_PROTOCOL)
            .map_err(RpassManagerError::GpgContext)?;
        Ok(RpassManager {
            store_dir: self.store_dir.clone(),
            key,
            context,
            git_enabled: self.git_enabled,
        })
    }

    pub fn pass_exists(&self, pass_name: String) -> bool {
        let file = self.pass_to_file(pass_name);
        file.exists()
    }

    /// Takes a clearstring password, encrypts it and saves it to the filesystem.
    /// The filepath will be store_dir/pass_name.gpg
    pub fn save_password(
        &mut self,
        pass_name: String,
        password: String,
    ) -> Result<(), RpassManagerError> {
        let filename = self.pass_to_file(pass_name);
        let mut output = File::create(filename).map_err(RpassManagerError::PasswordFile)?;
        self.context.set_armor(true);
        self.context
            .encrypt(vec![&self.key], password, &mut output)
            .map_err(RpassManagerError::GpgEncrypt)?;
        Ok(())
    }

    /// Fetches all the password names in the store. Meaning files with the .gpg extension.
    pub fn get_password_names(&self) -> Result<HashSet<String>, RpassManagerError> {
        let mut passwords: HashSet<String> = HashSet::new();
        for dir_entry in fs::read_dir(&self.store_dir).map_err(RpassManagerError::StoreDir)? {
            let dir_entry = dir_entry.map_err(RpassManagerError::DirEntry)?;
            let dir_entry = dir_entry.path();
            if let Some(ext) = dir_entry.extension() {
                if ext == "gpg" {
                    let file_name = dir_entry.file_stem().unwrap();
                    let file_name = file_name.to_str().unwrap();
                    passwords.insert(file_name.to_string());
                }
            }
        }
        Ok(passwords)
    }

    /// Returns the decrypted cleartext password with the given name as a Result.
    pub fn get_password(&mut self, pass_name: String) -> Result<String, RpassManagerError> {
        let filename = self.pass_to_file(pass_name);
        let mut input =
            File::open(filename).map_err(RpassManagerError::PasswordOpen)?;
        let mut output = Vec::new();
        self.context
            .decrypt(&mut input, &mut output)
            .map_err(RpassManagerError::GpgDecrypt)?;
        let result = std::str::from_utf8(&output).unwrap();
        Ok(result.trim().to_string())
    }

    pub fn pass_to_file(&self, pass_name: String) -> PathBuf {
        self.store_dir.clone().join(pass_name + ".gpg")
    }
}

pub fn get_user_key(username: &str) -> Result<Option<Key>, RpassManagerError> {
    let mut mode = KeyListMode::empty();
    mode.insert(KeyListMode::LOCAL);

    let mut ctx = Context::from_protocol(Protocol::OpenPgp)
        .map_err(RpassManagerError::GpgContext)?;

    ctx.set_key_list_mode(mode)
        .map_err(RpassManagerError::KeyListMode)?;
    let mut keys = ctx.secret_keys().map_err(RpassManagerError::SecretKeys)?;
    for key in keys.by_ref().filter_map(|x| x.ok()) {
        let name = key.user_ids().last().unwrap().address().unwrap();
        if username == name {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

fn is_git_dir(dir: &Path) -> bool {
    let exit_status = Command::new("git")
        .arg("-C")
        .arg(dir.to_str().unwrap())
        .arg("status")
        .output()
        .unwrap()
        .status
        .success();
    exit_status
}

pub fn read_gpg_id(store_dir: &Path) -> Result<String, RpassManagerError> {
    let gpg_id_filename = store_dir.to_str().unwrap().to_string() + GPG_ID_FILE_NAME;
    let mut gpg_id_file =
        fs::File::open(gpg_id_filename).map_err(RpassManagerError::StoreDir)?;
    let mut gpg_id = String::new();
    gpg_id_file
        .read_to_string(&mut gpg_id)
        .expect("Could not read gpg-id file");
    Ok(gpg_id)
}

#[cfg(test)]
mod tests {
    // Tests for the rpass library.
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_read_gpg_id() {
        let mut store_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        store_dir.push("tests");
        store_dir.push("test_store");
        let gpg_id = read_gpg_id(&store_dir).unwrap();
        assert_eq!(gpg_id, "janrossbach3@gmail.com");
    }
}
