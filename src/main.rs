use clap::{Args, Parser, Subcommand};
use regex::RegexSet;
use rpass::RpassManager;

use std::{str::FromStr, env, process::Command, io::{self, Read}, fs::File};

use home::home_dir;

use std::path::PathBuf;

mod rpass;

const RPASS_DEFAULT_STORE_NAME: &str = ".rpassword_store";


#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct RpassArgs {
    #[clap(subcommand)]
    command: RpassCommand,
}

#[derive(Debug, Subcommand)]
enum RpassCommand {
    /// Initialize new password storage and use gpg-id for encryption.
    /// Selectively reencrypt existing passwords using new gpg-id.
    Init(InitCommand),
    /// List passwords.
    Ls(LSCommand),
    /// List passwords that match pass-names.
    Find(FindCommand),
    /// Show existing password and optionally put it on the clipboard.
    Show(ShowCommand),
    /// Insert new password. Optionally, echo the password back to the console
    /// during entry. Prompt before overwriting existing password unless forced.
    Insert(InsertCommand),
    /// Insert a new password or edit an existing password using your $EDITOR or neovim as a fallback.
    Edit(EditCommand),
}

#[derive(Args, Debug)]
struct InitCommand {
    #[arg(short, long)]
    subfolder: Option<String>,

    gpg_id: String,
}

#[derive(Args, Debug)]
struct EditCommand {
    pass_name: String,
}

#[derive(Args, Debug)]
struct InsertCommand {
    pass_name: String,
    #[arg(short, long)]
    force: bool,
}

#[derive(Args, Debug)]
struct LSCommand {
    subfolder: Option<String>,
}

#[derive(Args, Debug)]
struct FindCommand {
    pass_names: Vec<String>,
}

#[derive(Args,Debug)]
struct ShowCommand {
    pass_name: String,
    #[arg(short, long)]
    clip: bool
}

fn main() {
    let args = RpassArgs::parse();

    let subfolder = match args {
        _ => "".to_string(),
    };

    let rpassword_store_dir = build_password_dir(subfolder);
    let mut manager = match rpass::RpassManager::new(rpassword_store_dir) {
        Ok(m) => m,
        Err(err) => { eprintln!("{}",err); return; }
    };

    // Sub Command dispatch.
    let command_result = match args.command {
        RpassCommand::Init(command) => init(&command.gpg_id),
        RpassCommand::Ls(_) => ls(&manager),
        RpassCommand::Find(command) => find(&manager, command.pass_names),
        RpassCommand::Show(command) => show(&mut manager, command.pass_name, command.clip),
        RpassCommand::Insert(command) => insert(&mut manager, command.pass_name, command.force),
        RpassCommand::Edit(command) => edit(&mut manager, command.pass_name),
    };

    // Error Handling
    match command_result {
        Ok(()) => (),
        Err(err) => {
            eprintln!("{}", err);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_password_dir() {
        assert_eq!(build_password_dir("".to_string()).to_str().unwrap(), "/home/jan/repositories/rpass/store/");
        assert_eq!(build_password_dir("jan".to_string()).to_str().unwrap(), "/home/jan/repositories/rpass/store/jan");
    }
}


fn ls(manager: &RpassManager) -> io::Result<()> {
    let pw_names = manager.get_password_names()?;
    println!("Password store:");
    for pw in pw_names {
        println!("|-- {}", pw);
    }
    Ok(())
}

// TODO
fn init(_gpg_id: &str) -> io::Result<()> {
    // let user_key: Key = match get_user_key(gpg_id)? {
    //     Some(key) => key,
    //     None => {
    //         println!("Key for {} not found! Consider generating one.", gpg_id);
    //         return Ok(());
    //     }
    // };

    // assert!(user_key.is_qualified());

    // let mut path = store_dir.clone();
    // create_dir_all(&path)?;
    // path.push(".gpg-id");
    // let mut file = File::create(&path)?;
    // file.write_all(gpg_id.as_bytes())?;
    Ok(())
}

fn insert(manager: &mut RpassManager, pass_name:String, force: bool) -> std::io::Result<()> {
    if manager.pass_exists(pass_name.clone()) && !force {
        if prompt_user("Password already exists. Override?") {
            println!("Overriding.");
        } else {
            println!("Abort.");
            return Ok(());
        }
    }

    let password = get_pass_from_user()?;
    manager.save_password(pass_name, password)
}

fn find(manager: &RpassManager, search_terms: Vec<String>) -> std::io::Result<()> {
    let regexes: Vec<_> = search_terms.iter()
        .map(|pass_name| format!(r".*{}.*", pass_name))
        .collect();
    let regex_set = RegexSet::new(regexes).unwrap();
    let password_names = manager.get_password_names()?;

    println!("Search Terms: {}",search_terms.join(","));
    for pw in password_names {
        if regex_set.matches(&pw).into_iter().count() > 0 {
            println!("|-- {}",pw);
        }
    }
    Ok(())
}

fn show(manager: &mut RpassManager, pass_name: String, clip: bool) -> std::io::Result<()> {

    let password = manager.get_password(pass_name)?;

    if clip {
        println!("Password put into clipboard!"); // FIXME
    } else {
        println!("{}", password);
    }
    Ok(())
}

fn edit(manager: &mut RpassManager, pass_name: String) -> std::io::Result<()> {

    if manager.pass_exists(pass_name.clone()) {

        let tmp_file: String = format!("/tmp/{}pwtempfile",pass_name);
        Command::new("vim")
            .arg(tmp_file.clone())
            .status()
            .expect("Failed to edit file in vim.");
        let mut file = File::open(tmp_file)?;
        let mut new_password = String::new();
        file.read_to_string(&mut new_password)?;

        manager.save_password(pass_name, new_password)?;
        return Ok(());
    }

    let password = get_pass_from_user()?;
    manager.save_password(pass_name, password)
}

fn get_pass_from_user() -> std::io::Result<String> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input)
}

fn prompt_user(message: &str) -> bool {
    println!("{} [y/n] ", message);
    let mut answer: [u8; 1] = [0];
    std::io::stdin().read_exact(&mut answer).unwrap();
    let res = match answer[0] as char {
        'y' => true,
        _ => false
    };
    // For some reason, after reading in with read_exact, rust just ignores the
    // next call to read_line. So here I just use one so it does not disrupt the
    // rest of the program. This seems like a bug...
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    res
}
