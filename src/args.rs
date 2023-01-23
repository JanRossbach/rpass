use clap:: {
    Args,
    Parser,
    Subcommand
};

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
}

#[derive(Args, Debug)]
pub struct InitCommand {
    #[arg(short,long)]
    pub subfolder: Option<String>,

    pub gpg_id: String,
}

#[derive(Args, Debug)]
pub struct LSCommand {
    pub subfolder: Option<String>
}
