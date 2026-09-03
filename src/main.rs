use std::path::PathBuf;

use archive_lint::{Report, lint_archive, render_json, render_text};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "archive-lint",
    version,
    about = "Audit tar archive metadata without extracting the archive"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(value_name = "ARCHIVE")]
    archive: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        name = "policy-check",
        about = "Apply the default strict extraction policy"
    )]
    PolicyCheck {
        #[arg(value_name = "ARCHIVE")]
        archive: PathBuf,

        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("archive-lint: {error}");
            1
        }
    };

    std::process::exit(exit_code);
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let (archive, format, policy_check) = match cli.command {
        Some(Command::PolicyCheck { archive, format }) => (archive, format, true),
        None => (
            cli.archive.ok_or("an archive path is required")?,
            cli.format,
            false,
        ),
    };

    let report = lint_archive(&archive, policy_check)?;
    print_report(&report, format)?;
    Ok(report.exit_code())
}

fn print_report(report: &Report, format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Text => print!("{}", render_text(report)),
        OutputFormat::Json => println!("{}", render_json(report)?),
    }
    Ok(())
}
