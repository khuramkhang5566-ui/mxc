// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only Windows directory and selected-SID ACL collection.

use std::ffi::c_void;
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

use anyhow::{bail, ensure, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, IsValidSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT};

use crate::model::{Directory, Inventory, Principal, Rights, ScanMode};
use crate::progress::ScanProgress;

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Windows allocated this buffer with LocalAlloc; it is owned here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

struct SelectedSid {
    sid: PSID,
    _allocation: LocalAllocation,
}

impl SelectedSid {
    fn new(principal: Principal) -> Result<Self> {
        let text: Vec<u16> = principal.sid().encode_utf16().chain(Some(0)).collect();
        let mut sid = PSID::default();
        // SAFETY: text is NUL-terminated; sid is a valid output pointer.
        unsafe {
            ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut sid)
                .context("cannot construct the selected application-package SID")?;
        }
        Ok(Self {
            sid,
            _allocation: LocalAllocation(sid.0),
        })
    }
}

fn read_rights(path: &Path, selected: &SelectedSid) -> Result<Rights> {
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut dacl = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: name is NUL-terminated and the output pointers remain live.
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    let _allocation = LocalAllocation(descriptor.0);
    ensure!(
        result == ERROR_SUCCESS,
        "cannot read directory ACL for {}: {result:?}",
        path.display()
    );
    let mut rights = Rights::default();
    if dacl.is_null() {
        // A null DACL is not a grant naming the selected group.
        return Ok(rights);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the returned DACL belongs to the still-owned security descriptor.
    unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .with_context(|| format!("cannot inspect ACL for {}", path.display()))?;
    }
    for index in 0..information.AceCount {
        let mut raw = ptr::null_mut();
        // SAFETY: index is within the ACE count returned for this live DACL.
        unsafe {
            GetAce(dacl, index, &mut raw)
                .with_context(|| format!("cannot read ACE {index} on {}", path.display()))?;
        }
        let raw = NonNull::new(raw).context("GetAce returned a null entry")?;
        // SAFETY: GetAce returned an ACE within the live security descriptor.
        let header = unsafe { raw.cast::<ACE_HEADER>().as_ref() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0 {
            continue;
        }
        ensure!(
            header.AceType <= 1,
            "unsupported DACL ACE type {} on {}",
            header.AceType,
            path.display()
        );
        ensure!(
            usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>(),
            "truncated ACE on {}",
            path.display()
        );
        // SAFETY: basic allowed/denied ACEs have the same Mask/SidStart layout,
        // and the size was checked. The descriptor keeps the variable SID alive.
        let ace = unsafe { raw.cast::<ACCESS_ALLOWED_ACE>().as_ref() };
        let sid = PSID(ptr::addr_of!(ace.SidStart).cast_mut().cast());
        // SAFETY: this SID is part of a basic ACE returned by Windows.
        ensure!(
            unsafe { IsValidSid(sid) }.as_bool(),
            "invalid ACE SID on {}",
            path.display()
        );
        // SAFETY: both SIDs are valid and their owning allocations are live.
        if unsafe { EqualSid(sid, selected.sid) }.is_ok() {
            rights.apply(ace.Mask, header.AceType == 1);
        }
    }
    Ok(rights)
}

fn display_path(path: &Path) -> Result<String> {
    let text = path.to_str().with_context(|| {
        format!(
            "path cannot be represented as JSON Unicode: {}",
            path.display()
        )
    })?;
    if let Some(unc) = text.strip_prefix("\\\\?\\UNC\\") {
        return Ok(format!("\\\\{unc}"));
    }
    if let Some(dos) = text.strip_prefix("\\\\?\\") {
        if dos.as_bytes().get(1) == Some(&b':') {
            return Ok(dos.to_owned());
        }
    }
    Ok(text.to_owned())
}

fn read_children(path: &Path, mode: ScanMode) -> Result<Vec<(PathBuf, bool)>> {
    let entries = fs::read_dir(path)
        .with_context(|| format!("cannot enumerate directory {}", path.display()))?;
    let mut children = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot enumerate {}", path.display()))?;
        let kind = entry
            .file_type()
            .with_context(|| format!("cannot inspect {}", entry.path().display()))?;
        if !kind.is_dir() && !kind.is_symlink() {
            continue;
        }
        let attributes = entry
            .metadata()
            .with_context(|| format!("cannot inspect {}", entry.path().display()))?
            .file_attributes();
        if attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            continue;
        }
        let reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
        if reparse && mode == ScanMode::Strict {
            bail!(
                "directory reparse point was not followed: {}; \
                 use --best-effort --report FILE to record unknown paths and continue",
                entry.path().display()
            );
        }
        children.push((entry.path(), reparse));
    }
    children.sort_unstable();
    Ok(children)
}

pub(crate) fn scan(
    paths: &[PathBuf],
    principal: Principal,
    mode: ScanMode,
    mut on_progress: impl FnMut(ScanProgress<'_>) -> Result<()>,
) -> Result<Inventory> {
    ensure!(!paths.is_empty(), "at least one scan root is required");
    let selected = SelectedSid::new(principal)?;
    let mut roots = Vec::new();
    for path in paths {
        let root = fs::canonicalize(path)
            .with_context(|| format!("cannot resolve scan root {}", path.display()))?;
        ensure!(
            root.is_dir(),
            "scan root is not a directory: {}",
            path.display()
        );
        roots.push(root);
    }
    roots.sort_by_key(|path| (path.components().count(), path.clone()));
    let mut unique: Vec<PathBuf> = Vec::new();
    for root in roots {
        if !unique.iter().any(|parent| root.starts_with(parent)) {
            unique.push(root);
        }
    }
    let mut pending: Vec<_> = unique
        .into_iter()
        .rev()
        .map(|root| (root, None, false))
        .collect();
    let mut inventory = Inventory {
        format_version: 2,
        principal,
        directories: Vec::new(),
    };
    let mut unknown = 0;
    while let Some((path, parent, reparse)) = pending.pop() {
        on_progress(ScanProgress {
            current: Some(&path),
            scanned: inventory.directories.len(),
            unknown,
            pending: pending.len(),
        })?;
        let collected = if reparse {
            Err(anyhow::anyhow!("directory reparse point was not followed"))
        } else {
            read_rights(&path, &selected)
                .and_then(|rights| read_children(&path, mode).map(|children| (rights, children)))
        };
        let (rights, children) = match collected {
            Ok(collected) => collected,
            Err(error) if mode == ScanMode::BestEffort => {
                inventory.directories.push(Directory {
                    path: display_path(&path)?,
                    parent,
                    volume_root: path.parent().is_none(),
                    allowed_mask: 0,
                    denied_mask: 0,
                    unknown_reason: Some(format!("{error:#}")),
                });
                unknown += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        let index = inventory.directories.len();
        inventory.directories.push(Directory {
            path: display_path(&path)?,
            parent,
            volume_root: path.parent().is_none(),
            allowed_mask: rights.allowed,
            denied_mask: rights.denied,
            unknown_reason: None,
        });
        pending.extend(
            children
                .into_iter()
                .rev()
                .map(|(child, reparse)| (child, Some(index), reparse)),
        );
    }
    on_progress(ScanProgress {
        current: None,
        scanned: inventory.directories.len(),
        unknown,
        pending: 0,
    })?;
    Ok(inventory)
}
