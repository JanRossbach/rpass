use clap::{Args, Parser, Subcommand};
use regex::RegexSet;
use std::collections::HashSet;
use std::io::Read;
use std::{env, fs};

use std::str::FromStr;

use home::home_dir;

use gpgme::{Context, Key, KeyListMode, Protocol};
use std::fs::{create_dir_all, File};
use std::{io::Write, path::PathBuf};

const RPASS_DEFAULT_STORE_NAME: &str = ".rpassword_store";
const GPG_ID_FILE_NAME: &str = "/.gpg-id";

fn read_gpg_id(store_dir: &PathBuf) -> std::io::Result<String> {
    let gpg_id_filename = store_dir.to_str().unwrap().to_string() + GPG_ID_FILE_NAME;
    let mut gpg_id_file = fs::File::open(gpg_id_filename)?;
    let mut gpg_id = String::new();
    gpg_id_file.read_to_string(&mut gpg_id)?;
    return Ok(gpg_id);
}

fn read_password_names(store_dir: &PathBuf) -> std::io::Result<HashSet<String>> {
    let mut passwords: HashSet<String> = HashSet::new();
    for dir_entry in fs::read_dir(store_dir)? {
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

pub fn ls(store_dir: PathBuf) -> std::io::Result<()> {
    let pw_names = read_password_names(&store_dir)?;
    println!("Password store:");
    for pw in pw_names {
        println!("|-- {}", pw);
    }
    Ok(())
}

fn init(gpg_id: &str, store_dir: PathBuf) -> std::io::Result<()> {
    let user_key: Key = match get_user_key(gpg_id) {
        Some(key) => key,
        None => {
            println!("Key for {} not found! Consider generating one.", gpg_id);
            return Ok(());
        }
    };

    assert!(user_key.is_qualified());

    let mut path = store_dir;
    create_dir_all(&path)?;
    path.push(".gpg-id");
    let mut file = File::create(&path)?;
    file.write_all(gpg_id.as_bytes())?;
    Ok(())
}

fn get_user_key(username: &str) -> Option<Key> {
    let mut mode = KeyListMode::empty();
    mode.insert(KeyListMode::LOCAL);

    let mut ctx = match Context::from_protocol(Protocol::OpenPgp) {
        Ok(it) => it,
        Err(err) => {
            println!("{:?}", err);
            return None;
        }
    };
    match ctx.set_key_list_mode(mode) {
        Ok(it) => it,
        Err(err) => {
            println!("{:?}", err);
            return None;
        }
    };
    let mut keys = match ctx.secret_keys() {
        Ok(it) => it,
        Err(err) => {
            println!("{:?}", err);
            return None;
        }
    };
    for key in keys.by_ref().filter_map(|x| x.ok()) {
        // FIXME
        let name = key.user_ids().last().unwrap().address().unwrap();
        if username == name {
            return Some(key);
        }
    }
    None
}


fn find(search_terms: Vec<String>, store_dir: PathBuf) -> std::io::Result<()> {
    let regexes: Vec<_> = search_terms.iter()
        .map(|pass_name| format!(r".*{}.*", pass_name))
        .collect();
    let regex_set = RegexSet::new(regexes).unwrap();
    let password_names = read_password_names(&store_dir)?;

    println!("Search Terms: {}",search_terms.join(","));
    for pw in password_names {
        if regex_set.matches(&pw).into_iter().count() > 0 {
            println!("|-- {}",pw);
        }
    }
    Ok(())
}

fn build_password_dir(subfolder: String) -> PathBuf {
    let default_store_dir = home_dir().unwrap().as_path().join(RPASS_DEFAULT_STORE_NAME);
    let mut rpassword_store_dir = match env::var("RPASSWORD_STORE_DIR") {
        Ok(s) => PathBuf::from_str(&s).unwrap_or(default_store_dir),
        Err(_err) => default_store_dir,
    };
    rpassword_store_dir.push(subfolder);
    rpassword_store_dir
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
pub struct RpassArgs {
    #[clap(subcommand)]
    pub command: RpassCommand,
}

#[derive(Debug, Subcommand)]
pub enum RpassCommand {
    /// Initialize new password storage and use gpg-id for encryption.
    /// Selectively reencrypt existing passwords using new gpg-id.
    Init(InitCommand),
    /// List passwords.
    Ls(LSCommand),
    /// List passwords that match pass-names.
    Find(FindCommand),
}

#[derive(Args, Debug)]
pub struct InitCommand {
    #[arg(short, long)]
    pub subfolder: Option<String>,

    pub gpg_id: String,
}

#[derive(Args, Debug)]
pub struct LSCommand {
    pub subfolder: Option<String>,
}

#[derive(Args, Debug)]
pub struct FindCommand {
    pub pass_names: Vec<String>,
}

fn main() {
    let args = RpassArgs::parse();

    let subfolder = match args {
        _ => "".to_string(),
    };

    let rpassword_store_dir = build_password_dir(subfolder);

    let command_result = match args.command {
        RpassCommand::Init(command) => init(&command.gpg_id, rpassword_store_dir),
        RpassCommand::Ls(_) => ls(rpassword_store_dir),
        RpassCommand::Find(command) => find(command.pass_names, rpassword_store_dir),
    };

    match command_result {
        Ok(()) => (),
        Err(err) => {
            eprintln!("{}", err);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_key() {
        assert!(get_user_key("janrossbach3@gmail.com").is_some());
        assert!(get_user_key("").is_none());
    }

    #[test]
    fn test_build_password_dir() {
        assert_eq!(build_password_dir("".to_string()).to_str().unwrap(), "/home/jan/repositories/rpass/store/");
        assert_eq!(build_password_dir("jan".to_string()).to_str().unwrap(), "/home/jan/repositories/rpass/store/jan");
    }
}
