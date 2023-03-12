use std::collections::HashSet;
use std::io::{self, Read};
use std::fs::{File, self};
use std::path::PathBuf;
use std::process::Command;

use gpgme::{Key, Context, Protocol, KeyListMode};

const GPG_ID_FILE_NAME: &str = "/.gpg-id";

pub struct RpassManager {
    store_dir: PathBuf,
    key: Key,
    context: Context,
    git_enabled: bool
}

impl RpassManager {

    pub fn new(store_dir: PathBuf) -> io::Result<Self> {
        let gpg_id = read_gpg_id(&store_dir)?;
        let key = get_user_key(&gpg_id)?.unwrap();
        let context = Context::from_protocol(Protocol::OpenPgp)?;
        let git_enabled = is_git_dir(&store_dir);
        Ok(RpassManager {
            store_dir,
            key,
            context,
            git_enabled
        })
    }

    pub fn pass_exists(self: &Self, pass_name: String) -> bool {
        let file = self.pass_to_file(pass_name);
        file.exists()
    }

    /// Takes a clearstring password, encrypts it and saves it to the filesystem.
    /// The filepath will be store_dir/pass_name.gpg
    pub fn save_password(self: &mut Self, pass_name: String, password: String) -> io::Result<()> {
        let filename = self.pass_to_file(pass_name);
        let mut output = File::create(filename)?;
        self.context.set_armor(true);
        self.context.encrypt(vec![&self.key], password, &mut output)?;
        Ok(())
    }

    /// Fetches all the password names in the store. Meaning files with the .gpg extension.
    pub fn get_password_names(self: &Self) -> io::Result<HashSet<String>> {
        let mut passwords: HashSet<String> = HashSet::new();
        for dir_entry in fs::read_dir(&self.store_dir)? {
            let dir_entry = dir_entry?;
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
    pub fn get_password(self: &mut Self, pass_name: String) -> io::Result<String> {
        let filename = self.pass_to_file(pass_name);
        let mut input = File::open(&filename)?;
        let mut output = Vec::new();
        self.context.decrypt(&mut input, &mut output)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}",e)))?;
        let result = std::str::from_utf8(&output).unwrap();
        Ok(result.trim().to_string())
    }

    pub fn pass_to_file(self: &Self,pass_name: String) -> PathBuf {
        self.store_dir.clone().join(pass_name + ".gpg")
    }
}

fn read_gpg_id(store_dir: &PathBuf) -> std::io::Result<String> {
    let gpg_id_filename = store_dir.to_str().unwrap().to_string() + GPG_ID_FILE_NAME;
    let mut gpg_id_file = fs::File::open(gpg_id_filename)?;
    let mut gpg_id = String::new();
    gpg_id_file.read_to_string(&mut gpg_id)?;
    return Ok(gpg_id);
}

pub fn get_user_key(username: &str) -> std::io::Result<Option<Key>> {
    let mut mode = KeyListMode::empty();
    mode.insert(KeyListMode::LOCAL);

    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_key_list_mode(mode)?;
    let mut keys = ctx.secret_keys()?;
    for key in keys.by_ref().filter_map(|x| x.ok()) {
        let name = key.user_ids().last().unwrap().address().unwrap();
        if username == name {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

fn is_git_dir(dir: &PathBuf) -> bool {
    let dir_arg = format!("--git-dir={}/.git",dir.to_str().unwrap());
    let exit_status = Command::new("git")
        .arg(dir_arg)
        .arg("status")
        .output().unwrap().status.success();
    exit_status
}
