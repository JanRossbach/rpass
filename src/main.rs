use clap::{Args, Parser, Subcommand};
use gpgme::Key;
use passwords::PasswordGenerator;
use regex::RegexSet;
use rpass::RpassManager;

use std::{str::FromStr, env, process::{Command, Stdio}, io::{self, Read, Write}, fs::{File, create_dir_all}, thread::sleep, time::Duration};

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
    /// Generate a new password of pass-length (or 25 if unspecified) with optionally no symbols.
    /// Optionally put it on the clipboard and clear board after 45 seconds.
    /// Prompt before overwriting existing password unless forced.
    /// optionally replace only the first line of an existing file with a new password.
    Generate(GenerateCommand),
    /// Remove existing password or directory, optionally forcefully.
    Rm(RemoveCommand),
    /// Copies old-path to new-path, optionally forcefully, selectively reencrypting.
    Cp(CopyCommand),
    /// Renames or moves old-path to new-path, optionally forcefully, selectively reencrypting.
    Mv(MoveCommand),
}

#[derive(Args, Debug)]
struct GenerateCommand {
    #[arg(short, long)]
    no_symbols: bool,
    #[arg(short, long)]
    clip: bool,
    #[arg(short, long)]
    force: bool,
    pass_name: String,
    pass_length: Option<usize>,
}

#[derive(Args, Debug)]
struct InitCommand {
    #[arg(short, long)]
    subfolder: Option<String>,

    gpg_id: String,
}

#[derive(Args, Debug)]
struct MoveCommand {
    old_name: String,
    new_name: String,
    #[arg(short, long)]
    force: bool,
}

#[derive(Args, Debug)]
struct RemoveCommand {
    pass_name: String,
    #[arg(short, long)]
    force: bool,
    #[arg(short, long)]
    recursive: bool,
}

#[derive(Args, Debug)]
struct CopyCommand {
    old_name: String,
    new_name: String,
    #[arg(short, long)]
    force: bool,
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


    // When calling init for the first time, we short circuit here before createing the pw-manager.
    if !rpassword_store_dir.exists() {
        match args.command {
            RpassCommand::Init(command) => {
                let result = init_new(&command.gpg_id, &rpassword_store_dir);
                match result {
                    Ok(()) => println!("Password Store successfully created at {:?}", rpassword_store_dir),
                    Err(err) => println!("Password Store create failed because: {}", err),
                };
                return;
            }
            _ => ()
        }
    }

    let mut manager = match rpass::RpassManager::new(rpassword_store_dir) {
        Ok(m) => m,
        Err(err) => { eprintln!("Password Manager could not be loaded because: {}",err); return; }
    };

    // Sub Command dispatch.
    let command_result = match args.command {
        RpassCommand::Init(command) => init_reencrypt(&manager, &command.gpg_id),
        RpassCommand::Ls(_) => ls(&manager),
        RpassCommand::Find(command) => find(&manager, command.pass_names),
        RpassCommand::Show(command) => show(&mut manager, command.pass_name, command.clip),
        RpassCommand::Insert(command) => insert(&mut manager, command.pass_name, command.force),
        RpassCommand::Edit(command) => edit(&mut manager, command.pass_name),
        RpassCommand::Generate(command) => generate(&mut manager, command),
        RpassCommand::Mv(command) => move_password(&mut manager, command),
        RpassCommand::Cp(command) => copy_password(&mut manager, command),
        RpassCommand::Rm(command) => remove_password(&mut manager, command),
    };

    // Error Handling
    match command_result {
        Ok(()) => (),
        Err(err) => {
            eprintln!("{}", err);
        }
    }
}

fn move_password(manager: &mut RpassManager, command: MoveCommand) -> io::Result<()> {

    let src_file = manager.pass_to_file(command.old_name);
    let target_file = manager.pass_to_file(command.new_name);

    let output = Command::new("mv")
        .arg(src_file)
        .arg(target_file)
        .arg("-v")
        .output()
        .expect("Failed to edit file in vim.");

    let result = std::str::from_utf8(&output.stdout);
    println!("{}",result.unwrap().trim());
    Ok(())
}

fn copy_password(manager: &mut RpassManager, command: CopyCommand) -> io::Result<()> {
    let src_file = manager.pass_to_file(command.old_name);
    let target_file = manager.pass_to_file(command.new_name);

    let output = Command::new("cp")
        .arg(src_file)
        .arg(target_file)
        .arg("-v")
        .output()
        .expect("Failed to edit file in vim.");

    let result = std::str::from_utf8(&output.stdout);
    println!("{}",result.unwrap().trim());
    Ok(())
}

fn remove_password(manager: &mut RpassManager,command: RemoveCommand) -> io::Result<()> {
    let file = manager.pass_to_file(command.pass_name.clone());

    let prompt = format!("Are you sure you would like to delete {}?", command.pass_name);

    // TODO subfolders

    if !manager.pass_exists(command.pass_name.clone()) {
        eprintln!("Password {} does not exist.",command.pass_name);
        return Ok(());
    }

    if !command.force {
        if prompt_user(&prompt) {
            println!("Deleting");
        } else {
            println!("Abort");
            return Ok(());
        }
    }

    let mut output = Command::new("rm");
    output.arg("-v");
    output.arg(file);

    if command.force {
        output.arg("-f");
    }

    if command.recursive {
        output.arg("-r");
    }

    let output = output.output().expect("Failed to remove Password File.");

    let result = std::str::from_utf8(&output.stdout);
    println!("{}",result.unwrap().trim());
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

fn init_new(gpg_id: &str, store_dir: &PathBuf) -> io::Result<()> {
    let user_key: Key = match rpass::get_user_key(gpg_id)? {
        Some(key) => key,
        None => {
            println!("Key for {} not found! Consider generating one.", gpg_id);
            return Ok(());
        }
    };

    assert!(user_key.is_qualified());

    let mut path = store_dir.clone();
    create_dir_all(&path)?;
    path.push(".gpg-id");
    let mut file = File::create(&path)?;
    file.write_all(gpg_id.as_bytes())?;
    Ok(())
}

fn init_reencrypt(_manager: &RpassManager,_gpg_id: &str) -> io::Result<()> {
    // TODO
    todo!();
}

fn insert(manager: &mut RpassManager, pass_name:String, force: bool) -> io::Result<()> {
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

fn find(manager: &RpassManager, search_terms: Vec<String>) -> io::Result<()> {
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

fn show(manager: &mut RpassManager, pass_name: String, clip: bool) -> io::Result<()> {

    let password = manager.get_password(pass_name.clone())?;

    if clip {
        into_clipboard(password)?;
        println!("Copied {} to clipboard. Will clear in 45 seconds.", pass_name);
        sleep(Duration::from_millis(45000));
        into_clipboard("".to_string())?;
        println!("Clipboard cleared.");
    } else {
        println!("{}", password);
    }
    Ok(())
}

fn into_clipboard(output: String) -> io::Result<()> {
    let mut xclip = Command::new("xclip")
        .arg("-selection")
        .arg("clipboard")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let xclip_stdin = xclip.stdin.as_mut().unwrap();
    xclip_stdin.write_all(output.as_bytes())?;
    drop(xclip_stdin);
    xclip.wait()?;
    Ok(())
}

fn edit(manager: &mut RpassManager, pass_name: String) -> io::Result<()> {

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

fn generate(manager: &mut RpassManager, command: GenerateCommand) -> io::Result<()> {
    let pg = PasswordGenerator {
        length: command.pass_length.unwrap_or(25),
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: !command.no_symbols,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    };

    let pass_name = command.pass_name.clone();
    if manager.pass_exists(pass_name.clone()) && !command.force {
        if prompt_user("Password already exists. Override?") {
            println!("Overriding.");
        } else {
            println!("Abort.");
            return Ok(());
        }
    }

    let password = pg.generate_one().unwrap();
    manager.save_password(command.pass_name, password.clone())?;

    if command.clip {
        into_clipboard(password.clone())?;
        println!("Copied {} to clipboard. Will clear in 45 seconds.", pass_name);
        sleep(Duration::from_millis(45000));
        into_clipboard("".to_string())?;
        println!("Clipboard cleared.");
    } else {
        println!("{}", password);
    }

    Ok(())
}

fn get_pass_from_user() -> io::Result<String> {
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
