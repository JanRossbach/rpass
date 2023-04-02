use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use fork::{daemon, Fork};
use gpgme::Key;
use passwords::PasswordGenerator;
use regex::RegexSet;
use rpass::{RpassManager, RpassManagerError};
use thiserror::Error;

use std::{
    env,
    fs::{self, create_dir_all, File},
    io::{self, Read, Write},
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
    thread::sleep,
    time::Duration,
};

use home::home_dir;

use std::path::PathBuf;

mod rpass;

const RPASS_DEFAULT_STORE_NAME: &str = ".password-store";

#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct RpassArgs {
    #[clap(subcommand)]
    command: RpassCommand,
}

#[derive(Debug, Error)]
enum RpassError {
    #[error("An error occurred interacting with the Manager: {0}")]
    RpassManager(#[from] rpass::RpassManagerError),
    #[error("File System Error: {0}")]
    FileSystem(#[from] io::Error),
    #[error("Error Spawning external Command: {0}")]
    Process(io::Error),
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
    /// If the password store is a git repository, execute a git command specified by git-command-args.
    Git(GitCommand),
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

#[derive(Args, Debug, Clone)]
struct InitCommand {
    #[arg(short, long)]
    subfolder: Option<String>,

    gpg_id: String,
}

#[derive(Args, Debug)]
struct GitCommand {
    git_command_args: Vec<String>,
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

#[derive(Args, Debug)]
struct ShowCommand {
    pass_name: String,
    #[arg(short, long)]
    clip: bool,
}


fn main() {
    let args = RpassArgs::parse();

    let store_dir = args_to_store_dir(&args);

    // When calling init for the first time, we short circuit here before createing the pw-manager.
    if !store_dir.exists() {
        if let RpassCommand::Init(InitCommand { gpg_id, .. }) = args.command {
            match init_new(&gpg_id, &store_dir) {
                Ok(_) => println!("Initialized new password store at {}", store_dir.display()),
                Err(e) => println!("Failed to initialize new password store: {}", e),
            }
            return;
        }
    }

    let mut manager = match rpass::RpassManager::new(store_dir.clone()) {
        Ok(m) => m,
        Err(e) => {
            println!("Failed to initialize password store: {}", e);
            return;
        }
    };

    // Sub Command dispatch. Every subcommand is responsible for printing its own output.
    let result = match args.command {
        RpassCommand::Init(InitCommand { gpg_id, .. }) => init_reencrypt(&mut manager, &gpg_id),
        RpassCommand::Ls(_) => ls(&manager),
        RpassCommand::Find(command) => find(&manager, command.pass_names),
        RpassCommand::Show(command) => show(&mut manager, command.pass_name, command.clip),
        RpassCommand::Insert(command) => insert(&mut manager, command.pass_name, command.force),
        RpassCommand::Edit(command) => edit(&mut manager, command.pass_name),
        RpassCommand::Generate(command) => generate(&mut manager, command),
        RpassCommand::Mv(command) => move_password(&mut manager, command),
        RpassCommand::Cp(command) => copy_password(&mut manager, command),
        RpassCommand::Rm(command) => remove_password(&mut manager, command),
        RpassCommand::Git(command) => git_run(&store_dir, command.git_command_args),
    };

    match result {
        Ok(_) => (),
        Err(e) => println!("Error: {}", e),
    }
}

// Run git command in the password store directory.
fn git_run(store_dir: &Path, git_command_args: Vec<String>) -> Result<(), RpassError> {
    let mut cmd = Command::new("git")
        .arg("-C")
        .arg(store_dir.to_str().unwrap())
        .args(git_command_args)
        .spawn()
        .map_err(RpassError::Process)?;
    cmd.wait().map_err(RpassError::Process)?;
    Ok(())
}

fn move_password(manager: &mut RpassManager, command: MoveCommand) -> Result<(), RpassError> {
    let src_file = manager.pass_to_file(command.old_name.clone());
    let target_file = manager.pass_to_file(command.new_name.clone());

    let output = Command::new("mv")
        .arg(src_file)
        .arg(target_file)
        .arg("-v")
        .output()
        .map_err(RpassError::Process)?;

    let result = std::str::from_utf8(&output.stdout);
    println!("{}", result.unwrap().trim());

    if manager.git_enabled {
        git_commit_with_msg(
            &manager.store_dir,
            format!("Renamed {} to {}", command.old_name, command.new_name),
        )?;
    }
    Ok(())
}

fn copy_password(manager: &mut RpassManager, command: CopyCommand) -> Result<(), RpassError> {
    let src_file = manager.pass_to_file(command.old_name.clone());
    let target_file = manager.pass_to_file(command.new_name.clone());

    let output = Command::new("cp")
        .arg(src_file)
        .arg(target_file)
        .arg("-v")
        .output()
        .map_err(RpassError::Process)?;

    if manager.git_enabled {
        git_commit_with_msg(
            &manager.store_dir,
            format!("Copied {} to {}", command.old_name, command.new_name),
        )?;
    }

    let result = std::str::from_utf8(&output.stdout);
    println!("{}", result.unwrap().trim());
    Ok(())
}

fn remove_password(manager: &mut RpassManager, command: RemoveCommand) -> Result<(), RpassError> {
    let file = manager.pass_to_file(command.pass_name.clone());

    let prompt = format!(
        "Are you sure you would like to delete {}?",
        command.pass_name
    );

    if !manager.pass_exists(command.pass_name.clone()) {
        eprintln!("Password {} does not exist.", command.pass_name);
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
    println!("{}", result.unwrap().trim());

    if manager.git_enabled {
        git_commit_with_msg(&manager.store_dir, format!("Removed {}", command.pass_name))?;
    }
    Ok(())
}

fn ls(manager: &RpassManager) -> Result<(), RpassError> {
    println!("{}", "Password Store".blue().bold());
    let tree = Command::new("tree")
        .arg("-C")
        .arg("-l")
        .arg("--noreport")
        .arg(manager.store_dir.to_str().unwrap())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(RpassError::Process)?;
    let tail = Command::new("tail")
        .arg("-n")
        .arg("+2")
        .stdin(tree.stdout.unwrap())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to execute tail");
    Command::new("sed")
        .arg("-E")
        .arg(r"s/\.gpg(\x1B\[[0-9]+m)?( ->|$)/\1\2/g")
        .stdin(tail.stdout.unwrap())
        .spawn()
        .map_err(RpassError::Process)?;
    Ok(())
}

fn init_new(gpg_id: &str, store_dir: &Path) -> Result<(), RpassError> {
    let _user_key: Key = match rpass::get_user_key(gpg_id).map_err(RpassError::RpassManager)? {
        Some(key) => key,
        None => {
            return Err(RpassError::RpassManager(RpassManagerError::KeyNotFound(
                io::Error::new(io::ErrorKind::NotFound, "Key not found"),
            )));
        }
    };
    let mut path: PathBuf = store_dir.to_path_buf();
    create_dir_all(&path).map_err(RpassError::FileSystem)?;
    path.push(".gpg-id");
    let mut file = File::create(&path).map_err(RpassError::FileSystem)?;
    file.write_all(gpg_id.as_bytes())
        .map_err(RpassError::FileSystem)?;
    Ok(())
}

fn init_reencrypt(manager: &mut RpassManager, gpg_id: &str) -> Result<(), RpassError> {
    let mut new_manager = manager.change_key(gpg_id)?;
    let passwords = manager.get_password_names()?;
    for pass_name in passwords {
        let password = manager.get_password(pass_name.clone())?;
        new_manager
            .save_password(pass_name, password)
            .map_err(RpassError::RpassManager)?;
    }
    Ok(())
}

fn insert(manager: &mut RpassManager, pass_name: String, force: bool) -> Result<(), RpassError> {
    if manager.pass_exists(pass_name.clone()) && !force {
        if prompt_user("Password already exists. Override?") {
            println!("Overriding.");
        } else {
            println!("Abort.");
            return Ok(());
        }
    }

    let password = get_pass_from_user().expect("Failed to get password from user.");
    manager.save_password(pass_name.clone(), password)?;

    if manager.git_enabled {
        git_commit_with_msg(&manager.store_dir, format!("Added {}", pass_name))?;
    }
    Ok(())
}

fn find(manager: &RpassManager, search_terms: Vec<String>) -> Result<(), RpassError> {
    let regexes: Vec<_> = search_terms
        .iter()
        .map(|pass_name| format!(r".*{}.*", pass_name))
        .collect();
    let regex_set = RegexSet::new(regexes).unwrap();
    let password_names = manager.get_password_names()?;

    println!("Search Terms: {}", search_terms.join(","));
    for pw in password_names {
        if regex_set.matches(&pw).into_iter().count() > 0 {
            println!("|-- {}", pw);
        }
    }
    Ok(())
}

fn show(manager: &mut RpassManager, pass_name: String, clip: bool) -> Result<(), RpassError> {
    let password = manager.get_password(pass_name.clone())?;

    if clip {
        into_clipboard(password)?;
        println!(
            "Copied {} to clipboard. Will clear in 45 seconds.",
            pass_name
        );
        if let Ok(Fork::Child) = daemon(false, false) {
            sleep(Duration::from_millis(45000));
            into_clipboard("".to_string())?;
            println!("Clipboard cleared.");
        }
    } else {
        println!("{}", password);
    }
    Ok(())
}

fn into_clipboard(output: String) -> Result<(), RpassError> {
    let mut xclip = Command::new("xclip")
        .arg("-selection")
        .arg("clipboard")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(RpassError::Process)?;
    let xclip_stdin = xclip.stdin.as_mut().unwrap();
    xclip_stdin
        .write_all(output.as_bytes())
        .map_err(RpassError::Process)?;
    xclip.wait().map_err(RpassError::Process)?;
    Ok(())
}

fn git_commit_with_msg(dir: &Path, msg: String) -> Result<(), RpassError> {
    git_run(dir, vec!["add".to_string(), "*".to_string()])?;
    git_run(dir, vec!["commit".to_string(), "-m".to_string(), msg])?;
    Ok(())
}

fn edit(manager: &mut RpassManager, pass_name: String) -> Result<(), RpassError> {
    let tmp_file: String = format!(
        "{}{}pwtempfile",
        manager.store_dir.to_str().unwrap(),
        pass_name
    );

    if manager.pass_exists(pass_name.clone()) {
        let old_password = manager.get_password(pass_name.clone())?;
        let mut file = File::create(tmp_file.clone()).map_err(RpassError::FileSystem)?;
        file.write_all(old_password.as_bytes())
            .map_err(RpassError::FileSystem)?;
    } else {
        println!("Hello");
    }

    Command::new("vim")
        .arg(tmp_file.clone())
        .status()
        .map_err(RpassError::Process)?;
    let mut file = File::open(tmp_file.clone()).map_err(RpassError::FileSystem)?;
    let mut new_password = String::new();
    file.read_to_string(&mut new_password)
        .expect("Failed to read temporary file.");
    fs::remove_file(tmp_file).map_err(RpassError::FileSystem)?;

    manager.save_password(pass_name.clone(), new_password)?;

    if manager.git_enabled {
        git_commit_with_msg(&manager.store_dir, format!("Edited {}", pass_name))?;
    }
    Ok(())
}

fn generate(manager: &mut RpassManager, command: GenerateCommand) -> Result<(), RpassError> {
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
        into_clipboard(password)?;
        println!(
            "Copied {} to clipboard. Will clear in 45 seconds.",
            pass_name
        );
        if let Ok(Fork::Child) = daemon(false, false) {
            sleep(Duration::from_millis(45000));
            into_clipboard("".to_string())?;
            println!("Clipboard cleared.");
        }
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
    let res = matches!(answer[0] as char, 'y');
    // For some reason, after reading in with read_exact, rust just ignores the
    // next call to read_line. So here I just use one so it does not disrupt the
    // rest of the program. This seems like a bug...
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    res
}

fn args_to_store_dir(args: &RpassArgs) -> PathBuf {
    // The store_base_dir is either in determined by the env or the default dir.
    let default_store_dir = home_dir().unwrap().as_path().join(RPASS_DEFAULT_STORE_NAME);
    let mut rpassword_store_dir = match env::var("RPASSWORD_STORE_DIR") {
        Ok(s) => PathBuf::from_str(&s).unwrap_or(default_store_dir),
        Err(_err) => default_store_dir,
    };

    let subfolder = match args.command {
        RpassCommand::Init(InitCommand {
            subfolder: Some(ref s),
            ..
        }) => s.to_string(),
        RpassCommand::Ls(LSCommand {
            subfolder: Some(ref s),
        }) => s.to_string(),
        _ => "".to_string(),
    };
    rpassword_store_dir.push(subfolder);
    rpassword_store_dir
}
