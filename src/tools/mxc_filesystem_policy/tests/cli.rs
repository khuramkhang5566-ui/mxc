// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::process::Command;

use anyhow::Result;
use serde_json::{json, Value};

fn inventory(principal: &str, child_mask: u32) -> Value {
    json!({
        "formatVersion": 1,
        "principal": principal,
        "directories": [
            {
                "path": "C:\\Data", "parent": null, "volumeRoot": false,
                "allowedMask": 0x001200a9u32, "deniedMask": 0
            },
            {
                "path": "C:\\Data\\Private", "parent": 0, "volumeRoot": false,
                "allowedMask": child_mask, "deniedMask": 0
            }
        ]
    })
}

#[test]
fn exports_a_fragment_without_mixing_diagnostics_into_json() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inventory.json");
    fs::write(
        &input,
        serde_json::to_vec(&inventory("ALL_APPLICATION_PACKAGES", 0))?,
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(input)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        actual,
        json!({
            "filesystem": {
                "readwritePaths": [],
                "readonlyPaths": ["C:\\Data"],
                "deniedPaths": ["C:\\Data\\Private"]
            }
        })
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("not explicit MXC denies"));
    Ok(())
}

#[test]
fn unrepresentable_rights_do_not_replace_an_existing_output() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inventory.json");
    let destination = directory.path().join("fragment.json");
    fs::write(
        &input,
        serde_json::to_vec(&inventory("ALL_APPLICATION_PACKAGES", 2))?,
    )?;
    fs::write(&destination, "original")?;
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(input)
        .arg("--out")
        .arg(&destination)
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(destination)?, "original");
    assert!(String::from_utf8_lossy(&output.stderr).contains("C:\\Data\\Private"));
    Ok(())
}

#[test]
fn saved_principal_is_preserved_and_cannot_be_reinterpreted() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inventory.json");
    fs::write(
        &input,
        serde_json::to_vec(&inventory("ALL_RESTRICTED_APPLICATION_PACKAGES", 0))?,
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(&input)
        .output()?;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ALL_RESTRICTED_APPLICATION_PACKAGES"));
    let mismatch = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(input)
        .args(["--principal", "all-application-packages"])
        .output()?;
    assert!(!mismatch.status.success());
    assert!(mismatch.stdout.is_empty());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("does not match"));
    Ok(())
}

#[test]
fn an_output_alias_cannot_overwrite_the_input_inventory() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inventory.json");
    let bytes = serde_json::to_vec(&inventory("ALL_APPLICATION_PACKAGES", 0))?;
    fs::write(&input, &bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(&input)
        .arg("--out")
        .arg(directory.path().join(".").join("inventory.json"))
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(input)?, bytes);
    assert!(String::from_utf8_lossy(&output.stderr).contains("must differ"));
    Ok(())
}

#[test]
fn partial_fragments_require_and_preserve_an_explicit_coverage_report() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("inventory.json");
    let report = directory.path().join("coverage.json");
    let mut data = inventory("ALL_APPLICATION_PACKAGES", 0);
    data["formatVersion"] = json!(2);
    data["directories"][1]["unknownReason"] = json!("directory reparse point was not followed");
    fs::write(&input, serde_json::to_vec(&data)?)?;

    let strict = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(&input)
        .output()?;
    assert!(!strict.status.success());
    assert!(strict.stdout.is_empty());

    let missing_report = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(&input)
        .arg("--best-effort")
        .output()?;
    assert!(!missing_report.status.success());
    assert!(missing_report.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing_report.stderr).contains("--report"));

    let partial = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(&input)
        .arg("--best-effort")
        .arg("--report")
        .arg(&report)
        .output()?;
    assert!(
        partial.status.success(),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    let fragment: Value = serde_json::from_slice(&partial.stdout)?;
    assert_eq!(fragment["filesystem"]["deniedPaths"], json!([]));
    assert_eq!(fragment["filesystem"]["readonlyPaths"], json!(["C:\\Data"]));
    let coverage: Value = serde_json::from_slice(&fs::read(report)?)?;
    assert_eq!(coverage["complete"], false);
    assert_eq!(coverage["unknownPaths"][0]["path"], "C:\\Data\\Private");
    assert_eq!(coverage["unknownPaths"][0]["scope"], "subtree");
    assert!(String::from_utf8_lossy(&partial.stderr).contains("PARTIAL"));
    Ok(())
}
