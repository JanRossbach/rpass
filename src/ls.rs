use std::{path::PathBuf, fs};

use crate::args::LSCommand;


pub fn ls(command: LSCommand, store_directory: &PathBuf) -> Result<(), std::io::Error> {

    let mut path = store_directory.to_path_buf();

    path.push(command.subfolder.unwrap_or("".to_string()));

    match fs::read_dir(path) {
        Err(why) => println!("! {:?}", why.kind()),
        Ok(paths) => for path in paths {
            println!("> {:?}", path.unwrap().path());
        },
    }

    Ok(())
}
