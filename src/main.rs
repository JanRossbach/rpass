use clap::{Args, Parser, Subcommand};
use fork::{daemon, Fork};
use gpgme::Key;
use passwords::PasswordGenerator;
use regex::RegexSet;
use rpass::RpassManager;

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

fn main() {
    let args = RpassArgs::parse();

    let store_dir = args_to_store_dir(&args);

    // When calling init for the first time, we short circuit here before createing the pw-manager.
    if !store_dir.exists() {
        if let RpassCommand::Init(InitCommand { gpg_id, .. }) = args.command {
            init_new(&gpg_id, &store_dir);
            return;
        }
    }

    let mut manager = rpass::RpassManager::new(store_dir.clone());

    // Sub Command dispatch.
    match args.command {
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

}

fn git_run(store_dir: &Path, git_command_args: Vec<String>) {
    let _output = Command::new("git")
        .arg("-C")
        .arg(store_dir.to_str().unwrap())
        .args(git_command_args)
        .spawn();
}

fn move_password(manager: &mut RpassManager, command: MoveCommand) {
    let src_file = manager.pass_to_file(command.old_name.clone());
    let target_file = manager.pass_to_file(command.new_name.clone());

    let output = Command::new("mv")
        .arg(src_file)
        .arg(target_file)
        .arg("-v")
        .output()
        .expect("Failed to mv the File.");

    let result = std::str::from_utf8(&output.stdout);
    println!("{}", result.unwrap().trim());

    if manager.git_enabled {
        git_commit_with_msg(
            &manager.store_dir,
            format!("Renamed {} to {}", command.old_name, command.new_name),
        );
    }

}

fn copy_password(manager: &mut RpassManager, command: CopyCommand) {
    let src_file = manager.pass_to_file(command.old_name.clone());
    let target_file = manager.pass_to_file(command.new_name.clone());

    let output = Command::new("cp")
        .arg(src_file)
        .arg(target_file)
        .arg("-v")
        .output()
        .expect("Failed to edit file in vim.");

    if manager.git_enabled {
        git_commit_with_msg(
            &manager.store_dir,
            format!("Copied {} to {}", command.old_name, command.new_name),
        );
    }

    let result = std::str::from_utf8(&output.stdout);
    println!("{}", result.unwrap().trim());
}

fn remove_password(manager: &mut RpassManager, command: RemoveCommand) {
    let file = manager.pass_to_file(command.pass_name.clone());

    let prompt = format!(
        "Are you sure you would like to delete {}?",
        command.pass_name
    );

    if !manager.pass_exists(command.pass_name.clone()) {
        eprintln!("Password {} does not exist.", command.pass_name);
        return;
    }

    if !command.force {
        if prompt_user(&prompt) {
            println!("Deleting");
        } else {
            println!("Abort");
            return;
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
        git_commit_with_msg(&manager.store_dir, format!("Removed {}", command.pass_name));
    }

}

fn ls(manager: &RpassManager) {
    let pw_names = manager.get_password_names();
    println!("Password store:");
    for pw in pw_names {
        println!("|- {}", pw);
    }
}

fn init_new(gpg_id: &str, store_dir: &Path) {
    let _user_key: Key = match rpass::get_user_key(gpg_id) {
        Some(key) => key,
        None => {
            println!("Key for {} not found! Consider generating one.", gpg_id);
            return;
        }
    };

    let mut path: PathBuf = store_dir.to_path_buf();
    create_dir_all(&path).expect("Failed to create store directory.");
    path.push(".gpg-id");
    let mut file = File::create(&path).expect("Failed to create .gpg-id file.");
    file.write_all(gpg_id.as_bytes()).expect("Failed to write to .gpg-id file.");
}

fn init_reencrypt(manager: &mut RpassManager, gpg_id: &str) {
    let mut new_manager = manager.change_key(gpg_id);
    let passwords = manager.get_password_names();
    for pass_name in passwords {
        let password = manager.get_password(pass_name.clone());
        new_manager.save_password(pass_name, password);
    }
}

fn insert(manager: &mut RpassManager, pass_name: String, force: bool) {
    if manager.pass_exists(pass_name.clone()) && !force {
        if prompt_user("Password already exists. Override?") {
            println!("Overriding.");
        } else {
            println!("Abort.");
            return;
        }
    }

    let password = get_pass_from_user().expect("Failed to get password from user.");
    manager.save_password(pass_name.clone(), password);

    if manager.git_enabled {
        git_commit_with_msg(&manager.store_dir, format!("Added {}", pass_name));
    }
}

fn find(manager: &RpassManager, search_terms: Vec<String>) {
    let regexes: Vec<_> = search_terms
        .iter()
        .map(|pass_name| format!(r".*{}.*", pass_name))
        .collect();
    let regex_set = RegexSet::new(regexes).unwrap();
    let password_names = manager.get_password_names();

    println!("Search Terms: {}", search_terms.join(","));
    for pw in password_names {
        if regex_set.matches(&pw).into_iter().count() > 0 {
            println!("|-- {}", pw);
        }
    }
}

fn show(manager: &mut RpassManager, pass_name: String, clip: bool) {
    let password = manager.get_password(pass_name.clone());

    if clip {
        into_clipboard(password);
        println!(
            "Copied {} to clipboard. Will clear in 45 seconds.",
            pass_name
        );
        if let Ok(Fork::Child) = daemon(false, false) {
            sleep(Duration::from_millis(45000));
            into_clipboard("".to_string());
            println!("Clipboard cleared.");
        }
    } else {
        println!("{}", password);
    }
}

fn into_clipboard(output: String) {
    let mut xclip = Command::new("xclip")
        .arg("-selection")
        .arg("clipboard")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn().expect("Failed to spawn xclip.");
    let xclip_stdin = xclip.stdin.as_mut().unwrap();
    xclip_stdin.write_all(output.as_bytes()).expect("Failed to write to xclip stdin.");
    //drop(xclip_stdin);
    xclip.wait().expect("Failed to wait for xclip.");
}

fn git_commit_with_msg(dir: &Path, msg: String) {
    git_run(dir, vec!["add".to_string(), "*".to_string()]);
    git_run(dir, vec!["commit".to_string(), "-m".to_string(), msg]);
}

fn edit(manager: &mut RpassManager, pass_name: String) {
    let tmp_file: String = format!(
        "{}{}pwtempfile",
        manager.store_dir.to_str().unwrap(),
        pass_name
    );

    if manager.pass_exists(pass_name.clone()) {
        let old_password = manager.get_password(pass_name.clone());
        let mut file = File::open(tmp_file.clone()).expect("Failed to open temporary file.");
        file.write_all(old_password.as_bytes()).expect("Failed to write to temporary file.");
    } else {
        println!("Hello");
    }

    Command::new("vim")
        .arg(tmp_file.clone())
        .status()
        .expect("Failed to edit file in vim.");
    let mut file = File::open(tmp_file.clone()).expect("Failed to open temporary file.");
    let mut new_password = String::new();
    file.read_to_string(&mut new_password).expect("Failed to read temporary file.");
    fs::remove_file(tmp_file).expect("Failed to remove temporary file.");

    manager.save_password(pass_name.clone(), new_password);

    if manager.git_enabled {
        git_commit_with_msg(&manager.store_dir, format!("Edited {}", pass_name));
    }
}

fn generate(manager: &mut RpassManager, command: GenerateCommand) {
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
            return;
        }
    }

    let password = pg.generate_one().unwrap();
    manager.save_password(command.pass_name, password.clone());

    if command.clip {
        into_clipboard(password);
        println!(
            "Copied {} to clipboard. Will clear in 45 seconds.",
            pass_name
        );
        if let Ok(Fork::Child) = daemon(false, false) {
            sleep(Duration::from_millis(45000));
            into_clipboard("".to_string());
            println!("Clipboard cleared.");
        }
    } else {
        println!("{}", password);
    }
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
