const RPASS_STORE_NAME: &str = ".rpassword_store";

mod args;
mod init;
mod ls;


use args::RpassArgs;
use clap::Parser;
use home::home_dir;

use crate::args::RpassCommand::Init;
use crate::args::RpassCommand::Ls;


fn main() -> Result<(), std::io::Error> {
    let args = RpassArgs::parse();
    let store_directory = home_dir().unwrap().as_path().join(RPASS_STORE_NAME);
    match args.command {
        Init(command) => init::init(command, &store_directory),
        Ls (command) => ls::ls(command, &store_directory),
    }
}
