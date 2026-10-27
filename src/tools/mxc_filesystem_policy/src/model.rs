// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Selected-group rights and compact, documentation-only directory rules.

use std::collections::{HashMap, HashSet};

use anyhow::{bail, ensure, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

const READ_EXECUTE: u32 = 0x0012_00a9;
const MODIFY: u32 = 0x0013_01bf;
const FULL_CONTROL: u32 = 0x001f_01ff;
const WRITE_OR_DELETE: u32 = 0x0001_0156;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanMode {
    Strict,
    BestEffort,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub(crate) enum Principal {
    #[default]
    #[serde(rename = "ALL_APPLICATION_PACKAGES")]
    AllApplicationPackages,
    #[serde(rename = "ALL_RESTRICTED_APPLICATION_PACKAGES")]
    AllRestrictedApplicationPackages,
}

impl Principal {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::AllApplicationPackages => "ALL_APPLICATION_PACKAGES",
            Self::AllRestrictedApplicationPackages => "ALL_RESTRICTED_APPLICATION_PACKAGES",
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn sid(self) -> &'static str {
        match self {
            Self::AllApplicationPackages => "S-1-15-2-1",
            Self::AllRestrictedApplicationPackages => "S-1-15-2-2",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Inventory {
    pub(crate) format_version: u32,
    pub(crate) principal: Principal,
    pub(crate) directories: Vec<Directory>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Directory {
    pub(crate) path: String,
    pub(crate) parent: Option<usize>,
    /// Volume-root grants do not supply a recursive default to child directories.
    pub(crate) volume_root: bool,
    pub(crate) allowed_mask: u32,
    pub(crate) denied_mask: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) unknown_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CoverageReport {
    pub(crate) principal: Principal,
    pub(crate) complete: bool,
    pub(crate) directory_path_count: usize,
    pub(crate) unknown_paths: Vec<UnknownPath>,
    pub(crate) note: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnknownPath {
    pub(crate) path: String,
    pub(crate) scope: UnknownScope,
    pub(crate) reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum UnknownScope {
    Directory,
    Subtree,
}

#[derive(Debug)]
pub(crate) struct Generated {
    pub(crate) fragment: Fragment,
    pub(crate) coverage: CoverageReport,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct Fragment {
    pub(crate) filesystem: Filesystem,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Filesystem {
    pub(crate) readwrite_paths: Vec<String>,
    pub(crate) readonly_paths: Vec<String>,
    pub(crate) denied_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    None,
    ReadOnly,
    ReadWrite,
    Unknown,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default)]
pub(crate) struct Rights {
    pub(crate) allowed: u32,
    pub(crate) denied: u32,
}

#[cfg(any(target_os = "windows", test))]
impl Rights {
    pub(crate) fn apply(&mut self, mask: u32, deny: bool) {
        let mask = expand_generic(mask);
        // A bit is decided by the first applicable ACE mentioning it.
        if deny {
            self.denied |= mask & !self.allowed;
        } else {
            self.allowed |= mask & !self.denied;
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn expand_generic(mask: u32) -> u32 {
    let mut expanded = mask & 0x0fff_ffff;
    for (generic, concrete) in [
        (0x8000_0000, 0x0012_0089),
        (0x4000_0000, 0x0012_0116),
        (0x2000_0000, 0x0012_00a0),
        (0x1000_0000, FULL_CONTROL),
    ] {
        if mask & generic != 0 {
            expanded |= concrete;
        }
    }
    expanded
}

fn classify(directory: &Directory) -> Result<Access> {
    let mask = directory.allowed_mask;
    ensure!(
        (mask | directory.denied_mask) & !FULL_CONTROL == 0,
        "unsupported access mask on {}: allow=0x{mask:08X}, deny=0x{:08X}",
        directory.path,
        directory.denied_mask
    );
    if mask == 0 {
        return Ok(Access::None);
    }
    if mask & MODIFY == MODIFY {
        return Ok(Access::ReadWrite);
    }
    if mask & READ_EXECUTE == READ_EXECUTE && mask & WRITE_OR_DELETE == 0 {
        return Ok(Access::ReadOnly);
    }
    bail!(
        "rights on {} cannot be represented as no grant, read-and-execute, or modify: \
         allow=0x{mask:08X}; inspect this ACL rather than widening its grant",
        directory.path
    )
}

fn volume_root(path: &str) -> Result<bool> {
    ensure!(
        !path.contains('\0') && !path.contains('/'),
        "invalid Windows directory path: {path:?}"
    );
    let bytes = path.as_bytes();
    let (tail, root_components) =
        if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\" {
            (&path[3..], 0)
        } else if let Some(tail) = path.strip_prefix("\\\\?\\") {
            ensure!(
                tail.starts_with("Volume{"),
                "unsupported device path: {path}"
            );
            (tail, 1)
        } else if let Some(tail) = path.strip_prefix("\\\\") {
            (tail, 2)
        } else {
            bail!("directory path is not an absolute Windows path: {path}");
        };
    let trimmed = tail.trim_end_matches('\\');
    let components: Vec<_> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('\\').collect()
    };
    ensure!(
        components.len() >= root_components
            && components
                .iter()
                .all(|part| !part.is_empty() && *part != "." && *part != ".."),
        "directory path is not normalized: {path}"
    );
    let is_root = components.len() == root_components;
    ensure!(
        is_root || !path.ends_with('\\'),
        "non-root directory has a trailing separator: {path}"
    );
    Ok(is_root)
}

fn parent_path(path: &str) -> Result<Option<&str>> {
    if volume_root(path)? {
        return Ok(None);
    }
    let separator = path
        .rfind('\\')
        .with_context(|| format!("directory has no parent separator: {path}"))?;
    if separator == 2 && path.as_bytes().get(1) == Some(&b':') {
        Ok(Some(&path[..3]))
    } else {
        Ok(Some(&path[..separator]))
    }
}

fn path_key(path: &str) -> String {
    path.trim_end_matches('\\').to_lowercase()
}

fn validate(inventory: &Inventory, mode: ScanMode) -> Result<(Vec<Access>, Vec<UnknownPath>)> {
    ensure!(
        matches!(inventory.format_version, 1 | 2),
        "unsupported inventory format version"
    );
    ensure!(
        !inventory.directories.is_empty(),
        "inventory has no directories"
    );
    let mut paths = HashSet::new();
    let mut access = Vec::with_capacity(inventory.directories.len());
    let mut unknown = Vec::new();
    for (index, directory) in inventory.directories.iter().enumerate() {
        ensure!(
            directory.volume_root == volume_root(&directory.path)?,
            "incorrect volume-root status on {}",
            directory.path
        );
        ensure!(
            paths.insert(path_key(&directory.path)),
            "duplicate or case-colliding directory path: {}",
            directory.path
        );
        if let Some(parent) = directory.parent {
            ensure!(
                parent < index && !directory.volume_root,
                "invalid parent index or nested volume root on {}",
                directory.path
            );
            let parent_path = inventory.directories[parent].path.trim_end_matches('\\');
            let name = directory
                .path
                .strip_prefix(parent_path)
                .and_then(|suffix| suffix.strip_prefix('\\'))
                .with_context(|| format!("parent path does not match {}", directory.path))?;
            ensure!(
                !name.is_empty() && !name.contains('\\'),
                "{} is not an immediate child of {parent_path}",
                directory.path
            );
            ensure!(
                inventory.directories[parent].unknown_reason.is_none(),
                "skipped subtree {} cannot contain inventoried descendants",
                inventory.directories[parent].path
            );
        }
        ensure!(
            directory.allowed_mask & directory.denied_mask == 0,
            "overlapping decided allow/deny bits on {}",
            directory.path
        );
        let classification = match &directory.unknown_reason {
            Some(reason) => Err(anyhow::anyhow!(
                "uninspected subtree {}: {reason}",
                directory.path
            )),
            None => classify(directory),
        };
        match classification {
            Ok(level) => access.push(level),
            Err(error) if mode == ScanMode::BestEffort => {
                access.push(Access::Unknown);
                unknown.push(UnknownPath {
                    path: directory.path.clone(),
                    scope: if directory.unknown_reason.is_some() {
                        UnknownScope::Subtree
                    } else {
                        UnknownScope::Directory
                    },
                    reason: format!("{error:#}"),
                });
            }
            Err(error) => return Err(error),
        }
    }
    for root in inventory
        .directories
        .iter()
        .filter(|node| node.parent.is_none())
    {
        let mut ancestor = parent_path(&root.path)?;
        while let Some(path) = ancestor {
            ensure!(
                !paths.contains(&path_key(path)),
                "inventory root {} overlaps another inventoried directory: {path}",
                root.path
            );
            ancestor = parent_path(path)?;
        }
    }
    Ok((access, unknown))
}

pub(crate) fn generate(inventory: &Inventory, mode: ScanMode) -> Result<Generated> {
    let (access, mut unknown_paths) = validate(inventory, mode)?;
    let mut fragment = Fragment::default();
    // Emit a rule at each change from the parent's actual access. Denied branches
    // can contain further grants; absence of a group grant is not a global deny.
    for (index, directory) in inventory.directories.iter().enumerate() {
        let inherited = match directory.parent {
            Some(parent) if !inventory.directories[parent].volume_root => access[parent],
            _ => Access::None,
        };
        if access[index] == inherited {
            continue;
        }
        let paths = match access[index] {
            Access::None => &mut fragment.filesystem.denied_paths,
            Access::ReadOnly => &mut fragment.filesystem.readonly_paths,
            Access::ReadWrite => &mut fragment.filesystem.readwrite_paths,
            Access::Unknown => continue,
        };
        paths.push(directory.path.clone());
    }
    for paths in [
        &mut fragment.filesystem.readonly_paths,
        &mut fragment.filesystem.readwrite_paths,
        &mut fragment.filesystem.denied_paths,
    ] {
        paths.sort_by_cached_key(|path| (path.to_lowercase(), path.clone()));
    }
    verify(inventory, &access, &fragment)?;
    unknown_paths.sort_by_cached_key(|entry| (entry.path.to_lowercase(), entry.path.clone()));
    Ok(Generated {
        fragment,
        coverage: CoverageReport {
            principal: inventory.principal,
            complete: unknown_paths.is_empty(),
            directory_path_count: inventory.directories.len(),
            unknown_paths,
            note: "Unknown paths are outside the fragment's claims, even below a listed ancestor. \
                   Baseline exceptions are not explicit MXC denials.",
        },
    })
}

fn verify(inventory: &Inventory, expected: &[Access], fragment: &Fragment) -> Result<()> {
    let known: HashSet<_> = inventory
        .directories
        .iter()
        .map(|node| node.path.as_str())
        .collect();
    let mut rules = HashMap::new();
    for (paths, access) in [
        (&fragment.filesystem.readonly_paths, Access::ReadOnly),
        (&fragment.filesystem.readwrite_paths, Access::ReadWrite),
        (&fragment.filesystem.denied_paths, Access::None),
    ] {
        for path in paths {
            ensure!(
                known.contains(path.as_str()),
                "rule outside inventory: {path}"
            );
            ensure!(
                rules.insert(path.as_str(), access).is_none(),
                "conflicting rule: {path}"
            );
        }
    }
    let mut resolved = Vec::with_capacity(inventory.directories.len());
    for (index, directory) in inventory.directories.iter().enumerate() {
        if expected[index] == Access::Unknown {
            ensure!(
                !rules.contains_key(directory.path.as_str()),
                "unknown path cannot be emitted as a grant or deny: {}",
                directory.path
            );
            resolved.push(Access::Unknown);
            continue;
        }
        let inherited = match directory.parent {
            Some(parent) if !inventory.directories[parent].volume_root => resolved[parent],
            _ => Access::None,
        };
        let actual = rules
            .get(directory.path.as_str())
            .copied()
            .unwrap_or(inherited);
        ensure!(
            actual == expected[index],
            "generated fragment changes baseline access on {}",
            directory.path
        );
        resolved.push(actual);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(path: &str, parent: Option<usize>, mask: u32) -> Directory {
        Directory {
            path: path.into(),
            parent,
            volume_root: false,
            allowed_mask: mask,
            denied_mask: 0,
            unknown_reason: None,
        }
    }

    fn inventory(directories: Vec<Directory>) -> Inventory {
        Inventory {
            format_version: 1,
            principal: Principal::default(),
            directories,
        }
    }

    fn generate(inventory: &Inventory) -> Result<Fragment> {
        Ok(super::generate(inventory, ScanMode::Strict)?.fragment)
    }

    #[test]
    fn compacts_explicit_copies_and_preserves_empty_deny_holes() -> Result<()> {
        let inventory = inventory(vec![
            node("C:\\Windows\\WinSxS", None, READ_EXECUTE),
            node("C:\\Windows\\WinSxS\\Component", Some(0), READ_EXECUTE),
            node("C:\\Windows\\WinSxS\\Component\\r", Some(1), READ_EXECUTE),
            node("C:\\Windows\\WinSxS\\InstallTemp", Some(0), 0),
        ]);
        let fragment = generate(&inventory)?;
        assert_eq!(fragment.filesystem.readonly_paths, ["C:\\Windows\\WinSxS"]);
        assert_eq!(
            fragment.filesystem.denied_paths,
            ["C:\\Windows\\WinSxS\\InstallTemp"]
        );
        assert!(fragment.filesystem.readwrite_paths.is_empty());
        Ok(())
    }

    #[test]
    fn preserves_nested_regrants_and_readwrite_differences() -> Result<()> {
        let inventory = inventory(vec![
            node("C:\\Data", None, MODIFY),
            node("C:\\Data\\Private", Some(0), 0),
            node("C:\\Data\\Private\\Shared", Some(1), READ_EXECUTE),
            node("C:\\Data\\Private\\Shared\\Blocked", Some(2), 0),
            node("C:\\Data\\Readonly", Some(0), READ_EXECUTE),
            node("C:\\Data\\Readonly\\Writable", Some(4), MODIFY),
        ]);
        let fragment = generate(&inventory)?;
        assert_eq!(
            fragment.filesystem.readwrite_paths,
            ["C:\\Data", "C:\\Data\\Readonly\\Writable"]
        );
        assert_eq!(
            fragment.filesystem.readonly_paths,
            ["C:\\Data\\Private\\Shared", "C:\\Data\\Readonly"]
        );
        assert_eq!(
            fragment.filesystem.denied_paths,
            ["C:\\Data\\Private", "C:\\Data\\Private\\Shared\\Blocked"]
        );
        Ok(())
    }

    #[test]
    fn ungranted_parents_do_not_hide_granted_descendants() -> Result<()> {
        let inventory = inventory(vec![
            node("C:\\Data", None, 0),
            node("C:\\Data\\Allowed", Some(0), READ_EXECUTE),
        ]);
        let fragment = generate(&inventory)?;
        assert_eq!(fragment.filesystem.readonly_paths, ["C:\\Data\\Allowed"]);
        assert!(fragment.filesystem.denied_paths.is_empty());
        Ok(())
    }

    #[test]
    fn volume_roots_do_not_supply_recursive_grants() -> Result<()> {
        let mut root = node("C:\\", None, READ_EXECUTE);
        root.volume_root = true;
        let fragment = generate(&inventory(vec![
            root,
            node("C:\\Allowed", Some(0), READ_EXECUTE),
            node("C:\\Private", Some(0), 0),
        ]))?;
        assert_eq!(fragment.filesystem.readonly_paths, ["C:\\", "C:\\Allowed"]);
        assert!(fragment.filesystem.denied_paths.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_partial_rights_and_invalid_tree_data() {
        assert!(generate(&inventory(vec![node("C:\\Partial", None, 0x0012_0116)])).is_err());
        assert!(generate(&inventory(vec![
            node("C:\\Data", None, READ_EXECUTE),
            node("C:\\DataElsewhere", Some(0), READ_EXECUTE),
        ]))
        .is_err());
        assert!(generate(&inventory(vec![node("C:\\Cycle", Some(0), 0)])).is_err());
        assert!(generate(&inventory(vec![node("relative", None, READ_EXECUTE)])).is_err());
        assert!(generate(&inventory(vec![
            node("C:\\Data", None, READ_EXECUTE),
            node("C:\\Data\\Private", None, 0),
        ]))
        .is_err());
        assert!(generate(&inventory(vec![
            node("C:\\Data", None, READ_EXECUTE),
            node("c:\\data", None, 0),
        ]))
        .is_err());
    }

    #[test]
    fn dacl_order_and_generic_masks_determine_selected_group_rights() {
        let mut rights = Rights::default();
        rights.apply(0xa000_0000, false);
        rights.apply(READ_EXECUTE, true);
        assert_eq!(rights.allowed, READ_EXECUTE);
        assert_eq!(rights.denied, 0);

        let mut rights = Rights::default();
        rights.apply(0x0001_0000, true);
        rights.apply(0x1000_0000, false);
        assert_eq!(rights.allowed, FULL_CONTROL & !0x0001_0000);
        assert_eq!(rights.denied, 0x0001_0000);
    }

    #[test]
    fn verifier_detects_lost_carveouts() -> Result<()> {
        let inventory = inventory(vec![
            node("C:\\Data", None, READ_EXECUTE),
            node("C:\\Data\\Private", Some(0), 0),
        ]);
        let (access, _) = validate(&inventory, ScanMode::Strict)?;
        let mut fragment = generate(&inventory)?;
        fragment.filesystem.denied_paths.clear();
        assert!(verify(&inventory, &access, &fragment).is_err());
        Ok(())
    }

    #[test]
    fn unknown_subtrees_are_not_denies_or_inherited_grant_claims() -> Result<()> {
        let mut skipped = node("C:\\Data\\Alias", Some(0), 0);
        skipped.unknown_reason = Some("directory reparse point was not followed".into());
        let inventory = inventory(vec![node("C:\\Data", None, READ_EXECUTE), skipped]);
        assert!(generate(&inventory).is_err());
        let mut generated = super::generate(&inventory, ScanMode::BestEffort)?;
        assert_eq!(generated.fragment.filesystem.readonly_paths, ["C:\\Data"]);
        assert!(generated.fragment.filesystem.denied_paths.is_empty());
        assert!(!generated.coverage.complete);
        assert!(matches!(
            generated.coverage.unknown_paths[0].scope,
            UnknownScope::Subtree
        ));
        let (expected, _) = validate(&inventory, ScanMode::BestEffort)?;
        generated
            .fragment
            .filesystem
            .denied_paths
            .push("C:\\Data\\Alias".into());
        assert!(verify(&inventory, &expected, &generated.fragment).is_err());
        Ok(())
    }

    #[test]
    fn partial_rights_are_unknown_only_on_the_directory_not_its_known_children() -> Result<()> {
        let inventory = inventory(vec![
            node("C:\\Data", None, READ_EXECUTE),
            node("C:\\Data\\Partial", Some(0), 2),
            node("C:\\Data\\Partial\\Readable", Some(1), READ_EXECUTE),
        ]);
        let generated = super::generate(&inventory, ScanMode::BestEffort)?;
        assert_eq!(
            generated.fragment.filesystem.readonly_paths,
            ["C:\\Data", "C:\\Data\\Partial\\Readable"]
        );
        assert!(generated.fragment.filesystem.denied_paths.is_empty());
        assert!(matches!(
            generated.coverage.unknown_paths[0].scope,
            UnknownScope::Directory
        ));
        Ok(())
    }
}
