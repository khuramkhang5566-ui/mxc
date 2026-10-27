// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "windows")]

use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::ptr;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW allocated this buffer.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

fn set_acl(path: &Path, entries: &str) -> Result<()> {
    // Fixtures contain no user data; Everyone retains full control for cleanup.
    let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;WD){entries}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl is NUL-terminated and descriptor is a valid output pointer.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .context("cannot construct fixture DACL")?;
    }
    let _allocation = Descriptor(descriptor);
    let mut present = Default::default();
    let mut defaulted = Default::default();
    let mut dacl = ptr::null_mut();
    // SAFETY: descriptor is valid and remains owned throughout both API calls.
    unsafe {
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)?;
        ensure!(
            present.as_bool() && !dacl.is_null(),
            "fixture DACL is absent"
        );
        let result = SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(
                DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
            ),
            None,
            None,
            Some(dacl),
            None,
        );
        ensure!(
            result == ERROR_SUCCESS,
            "cannot set fixture ACL: {result:?}"
        );
    }
    Ok(())
}

fn display(path: &Path) -> Result<String> {
    let canonical = fs::canonicalize(path)?;
    let path = canonical.to_str().context("non-Unicode fixture path")?;
    Ok(path.strip_prefix("\\\\?\\").unwrap_or(path).to_owned())
}

#[test]
fn native_collection_compacts_grants_and_preserves_empty_and_nested_exceptions() -> Result<()> {
    let directory = tempfile::tempdir()?;
    set_acl(directory.path(), "(A;OICI;GRGX;;;AC)")?;
    let inherited = directory.path().join("Inherited");
    let protected = directory.path().join("Protected");
    let blocked = directory.path().join("Blocked");
    let writable = blocked.join("Writable");
    let empty = directory.path().join("InstallTemp");
    for path in [&inherited, &protected, &blocked, &writable, &empty] {
        fs::create_dir(path)?;
    }
    set_acl(&protected, "(A;;GRGX;;;AC)")?;
    set_acl(&blocked, "")?;
    set_acl(&empty, "")?;
    set_acl(&writable, "(A;;0x1301bf;;;AC)")?;
    let snapshot = directory.path().join("snapshot.json");
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--path")
        .arg(directory.path())
        .arg("--save-inventory")
        .arg(&snapshot)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fragment: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        fragment,
        json!({
            "filesystem": {
                "readwritePaths": [display(&writable)?],
                "readonlyPaths": [display(directory.path())?],
                "deniedPaths": [display(&blocked)?, display(&empty)?]
            }
        })
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(snapshot)
        .output()?;
    assert!(replay.status.success());
    assert_eq!(output.stdout, replay.stdout);

    let restricted = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--path")
        .arg(directory.path())
        .args(["--principal", "all-restricted-application-packages"])
        .output()?;
    assert!(restricted.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&restricted.stdout)?,
        json!({"filesystem": {"readwritePaths": [], "readonlyPaths": [], "deniedPaths": []}})
    );
    Ok(())
}

#[test]
fn native_unrepresentable_acl_fails_without_publishing_a_fragment() -> Result<()> {
    let directory = tempfile::tempdir()?;
    set_acl(directory.path(), "(A;;0x2;;;AC)")?;
    let destination = directory.path().join("fragment.json");
    let snapshot = directory.path().join("inventory.json");
    fs::write(&destination, "original")?;
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--path")
        .arg(directory.path())
        .arg("--out")
        .arg(&destination)
        .arg("--save-inventory")
        .arg(&snapshot)
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(destination)?, "original");
    let inventory: Value = serde_json::from_slice(&fs::read(snapshot)?)?;
    assert_eq!(inventory["directories"][0]["allowedMask"], 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be represented"));
    Ok(())
}

#[test]
fn best_effort_records_a_junction_cycle_and_partial_acl_without_denial_claims() -> Result<()> {
    let directory = tempfile::tempdir()?;
    set_acl(directory.path(), "(A;OICI;GRGX;;;AC)")?;
    let denied = directory.path().join("Denied");
    let partial = directory.path().join("Partial");
    let alias = directory.path().join("Alias");
    fs::create_dir(&denied)?;
    fs::create_dir(&partial)?;
    set_acl(&denied, "")?;
    set_acl(&partial, "(A;;0x2;;;AC)")?;
    let link = Command::new(std::env::var_os("ComSpec").context("ComSpec is missing")?)
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&alias)
        .arg(directory.path())
        .output()?;
    ensure!(
        link.status.success(),
        "cannot create junction fixture {}: {} {}",
        alias.display(),
        String::from_utf8_lossy(&link.stdout),
        String::from_utf8_lossy(&link.stderr)
    );
    let report = directory.path().join("coverage.json");
    let snapshot = directory.path().join("inventory.json");
    let strict = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--path")
        .arg(directory.path())
        .output()?;
    assert!(!strict.status.success());
    assert!(strict.stdout.is_empty());
    let output = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--path")
        .arg(directory.path())
        .arg("--best-effort")
        .arg("--report")
        .arg(&report)
        .arg("--save-inventory")
        .arg(&snapshot)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fragment: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        fragment["filesystem"]["deniedPaths"],
        json!([display(&denied)?])
    );
    let coverage: Value = serde_json::from_slice(&fs::read(report)?)?;
    assert_eq!(coverage["complete"], false);
    assert_eq!(coverage["unknownPaths"].as_array().map(Vec::len), Some(2));
    assert_eq!(coverage["unknownPaths"][0]["path"], display(&alias)?);
    assert_eq!(coverage["unknownPaths"][0]["scope"], "subtree");
    assert_eq!(coverage["unknownPaths"][1]["path"], display(&partial)?);
    assert_eq!(coverage["unknownPaths"][1]["scope"], "directory");
    let strict_replay = Command::new(env!("CARGO_BIN_EXE_mxc-filesystem-policy"))
        .arg("--inventory")
        .arg(&snapshot)
        .output()?;
    assert!(!strict_replay.status.success());
    assert!(strict_replay.stdout.is_empty());
    fs::remove_dir(alias)?;
    Ok(())
}
