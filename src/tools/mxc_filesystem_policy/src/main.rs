// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate a documentation fragment for application-package filesystem access.

mod model;
#[cfg(target_os = "windows")]
mod windows_scan;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{ensure, Context, Result};
use clap::{ArgGroup, Parser};
use model::{generate, Inventory, Principal, ScanMode};

#[derive(Debug, Parser)]
#[command(
    about = "Document application-package directory grants as an MXC filesystem fragment",
    long_about = "Document application-package directory grants as an MXC filesystem fragment.\n\
        This is a group-ACL baseline, not an executable replacement policy or a process access check.\n\
        deniedPaths are exceptions to that baseline, not explicit MXC policy denials.",
    group(ArgGroup::new("input").required(true).args(["path", "inventory"]))
)]
struct Cli {
    /// Directory to scan recursively. Repeat for multiple roots. Windows only.
    #[arg(long, value_name = "DIRECTORY")]
    path: Vec<PathBuf>,
    /// Read a previously saved inventory instead of accessing the filesystem.
    #[arg(long, value_name = "FILE")]
    inventory: Option<PathBuf>,
    /// Group to inspect. Defaults to all-application-packages for live scans.
    #[arg(long, value_enum)]
    principal: Option<Principal>,
    /// Save the inventory, including any best-effort unknown paths.
    #[arg(
        long,
        requires = "path",
        conflicts_with = "inventory",
        value_name = "FILE"
    )]
    save_inventory: Option<PathBuf>,
    /// Write the fragment to this file instead of stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Continue past uninspectable paths; requires a separate coverage report.
    #[arg(long, requires = "report")]
    best_effort: bool,
    /// Coverage report qualifying unknown paths in the partial fragment.
    #[arg(long, requires = "best_effort", value_name = "FILE")]
    report: Option<PathBuf>,
}

fn scan(paths: &[PathBuf], principal: Principal, mode: ScanMode) -> Result<Inventory> {
    #[cfg(target_os = "windows")]
    {
        windows_scan::scan(paths, principal, mode)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (paths, principal, mode);
        anyhow::bail!(
            "live ACL collection requires Windows; use --inventory for offline generation"
        )
    }
}

fn write_file(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create output in {}", parent.display()))?;
    temporary
        .write_all(content)
        .with_context(|| format!("cannot write {}", path.display()))?;
    temporary
        .persist(path)
        .with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

fn location_key(path: &Path) -> Result<String> {
    let absolute = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = fs::canonicalize(parent)
                .with_context(|| format!("cannot resolve output directory {}", parent.display()))?;
            parent.join(
                path.file_name()
                    .with_context(|| format!("output has no file name: {}", path.display()))?,
            )
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot resolve {}", path.display()))
        }
    };
    let name = absolute
        .to_str()
        .with_context(|| format!("non-Unicode output path: {}", absolute.display()))?;
    Ok(if cfg!(target_os = "windows") {
        name.to_lowercase()
    } else {
        name.to_owned()
    })
}

fn run(args: Cli) -> Result<()> {
    let mut locations = Vec::new();
    for path in [
        &args.out,
        &args.inventory,
        &args.save_inventory,
        &args.report,
    ]
    .into_iter()
    .flatten()
    {
        let destination = location_key(path)?;
        for location in &locations {
            ensure!(
                &destination != location,
                "fragment, inventory and coverage report paths must differ"
            );
        }
        locations.push(destination);
    }
    let mode = if args.best_effort {
        ScanMode::BestEffort
    } else {
        ScanMode::Strict
    };
    let inventory = match &args.inventory {
        Some(path) => {
            let bytes =
                fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            let inventory: Inventory = serde_json::from_slice(&bytes)
                .with_context(|| format!("cannot parse inventory {}", path.display()))?;
            if let Some(principal) = args.principal {
                ensure!(
                    principal == inventory.principal,
                    "--principal does not match the inventory's selected group"
                );
            }
            inventory
        }
        None => scan(&args.path, args.principal.unwrap_or_default(), mode)?,
    };
    if let Some(path) = &args.save_inventory {
        let mut bytes = serde_json::to_vec_pretty(&inventory)?;
        bytes.push(b'\n');
        write_file(path, &bytes)?;
    }
    let generated = generate(&inventory, mode)?;
    let mut content = serde_json::to_vec_pretty(&generated.fragment)?;
    content.push(b'\n');
    if let Some(path) = &args.report {
        let mut bytes = serde_json::to_vec_pretty(&generated.coverage)?;
        bytes.push(b'\n');
        write_file(path, &bytes)?;
    }
    match &args.out {
        Some(path) => write_file(path, &content)?,
        None => io::stdout()
            .lock()
            .write_all(&content)
            .context("cannot write fragment to stdout")?,
    }
    eprintln!(
        "Inventoried {} directory paths for {}: {} read-only grants, {} read-write grants, {} baseline exceptions.",
        inventory.directories.len(),
        inventory.principal.name(),
        generated.fragment.filesystem.readonly_paths.len(),
        generated.fragment.filesystem.readwrite_paths.len(),
        generated.fragment.filesystem.denied_paths.len()
    );
    if !generated.coverage.complete {
        eprintln!(
            "PARTIAL: {} unknown paths qualify the fragment, including any ancestor grants. \
             Use it only with the coverage report.",
            generated.coverage.unknown_paths.len()
        );
    }
    eprintln!(
        "Documentation only: baseline exceptions are not explicit MXC denies. \
         Explicit policy may grant access to exceptions or deny group-derived access."
    );
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mxc-filesystem-policy: {error:#}");
            ExitCode::FAILURE
        }
    }
}
