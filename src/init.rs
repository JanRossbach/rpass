use crate::args::InitCommand;
use std::{io::Write, path::PathBuf};
use std::fs::{File, create_dir_all};
use gpgme::{Context, KeyListMode, Protocol, Key};

pub fn init(command: InitCommand, root_dir: &PathBuf) -> Result<(), std::io::Error> {

    let gpg_id = &command.gpg_id;
    let mut path: PathBuf = match command.subfolder {
        Some(sub_folder) => root_dir.join(sub_folder),
        None => root_dir.to_path_buf()
    };

    let _user_key: Key = match get_user_key(gpg_id){
        Some(key) => key,
        None => {println!("Key for {} not found! Consider generating one.", gpg_id);return Ok(())}
    };

    match create_dir_all(&path) {
        Ok(_) => println!("Created directory {:?} for {}", path, gpg_id),
        Err(error) => {println!("{}",error);return Err(error)}
    }
    path.push(".gpg-id");
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };
    match file.write_all(gpg_id.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", display, why),
        Ok(_) => println!("successfully wrote to {}", display),
    }
    Ok(())
}


fn get_user_key(username: &str) -> Option<Key> {
    let mut mode = KeyListMode::empty();
    mode.insert(KeyListMode::LOCAL);

    let mut ctx = match Context::from_protocol(Protocol::OpenPgp) {
        Ok(it) => it,
        Err(err) => {println!("{:?}",err);return None},
    };
    match ctx.set_key_list_mode(mode) {
        Ok(it) => it,
        Err(err) => {println!("{:?}",err);return None},
    };
    let mut keys = match ctx.secret_keys() {
        Ok(it) => it,
        Err(err) => {println!("{:?}",err);return None},
    };
    for key in keys.by_ref().filter_map(|x| x.ok()){
        // FIXME
        let name = key.user_ids().last().unwrap().address().unwrap();
        if username == name {
            return Some(key)
        }
    }
    None
}


#[cfg(test)]
mod tests {
    use super::get_user_key;

    #[test]
    fn test_get_user_key() {
        assert!(get_user_key("janrossbach3@gmail.com").is_some());
        assert!(get_user_key("").is_none());
    }

}
