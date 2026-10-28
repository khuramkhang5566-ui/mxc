// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static INJECTION: OnceLock<(String, PathBuf)> = OnceLock::new();
static STALLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn stall(stage: &str, path: impl AsRef<Path>) {
    if INJECTION
        .get()
        .is_some_and(|(selected, target)| selected == stage && target == path.as_ref())
    {
        STALLED.store(true, Ordering::Release);
        loop {
            std::thread::park();
        }
    }
}

#[cfg(any(target_os = "linux", all(windows, feature = "wslc")))]
mod scenarios {
    use super::*;
    use crate::v1::{self, ContainerRequest, Containment, FilesystemPolicy};
    use std::fs::File;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const STAGE_ENV: &str = "MXC_FILESYSTEM_PROBE_TEST_STAGE";
    const DIRECTORY_ENV: &str = "MXC_FILESYSTEM_PROBE_TEST_DIRECTORY";
    const WATCHDOG: Duration = Duration::from_secs(15);

    fn exercise_request(backend: &str, provision: bool, stage: String, directory: &Path) {
        let target = directory.join("stalled-path");
        let marker = directory.join("workload-ran");
        std::fs::write(&target, b"readable").unwrap();
        let filesystem = FilesystemPolicy {
            readwrite_paths: vec![directory.to_str().unwrap().to_string()],
            readonly_paths: vec![target.to_str().unwrap().to_string()],
            ..Default::default()
        };
        assert!(INJECTION.set((stage, target.clone())).is_ok());
        let start = Instant::now();
        let result = if provision {
            let mut request = v1::ProvisionRequest::wslc(None, None);
            request.set_filesystem(filesystem);
            v1::container::provision_container(request, Default::default()).map(|result| {
                v1::container::deprovision_container(&result.container_id, Default::default())
                    .expect("clean up an unexpectedly provisioned container");
            })
        } else {
            let containment = match backend {
                "bubblewrap" => Containment::Bubblewrap,
                "lxc" => Containment::Lxc(Default::default()),
                "wslc" => Containment::Wslc(Default::default()),
                _ => panic!("unexpected backend: {backend}"),
            };
            let marker_path = if cfg!(windows) {
                let path = marker.to_str().unwrap().replace('\\', "/");
                format!("/mnt/{}/{}", path[..1].to_ascii_lowercase(), &path[3..])
            } else {
                marker.to_str().unwrap().to_string()
            };
            let command = format!("printf executed > '{}'", marker_path.replace('\'', "'\\''"));
            v1::spawn(
                ContainerRequest {
                    containment,
                    filesystem: Some(filesystem),
                    ..ContainerRequest::new(command)
                },
                Default::default(),
            )
            .map(drop)
        };
        let elapsed = start.elapsed();
        let error = result.expect_err("a stalled policy path must reject the request");
        assert!(
            STALLED.load(Ordering::Acquire),
            "the requested probe was not reached: {error}"
        );
        assert!(
            error.to_string().contains("timed out after 5000ms"),
            "{error}"
        );
        assert!(
            error.to_string().contains(
                &crate::mxc_common::config_deserialize::escape_diagnostic_text(
                    target.to_str().unwrap()
                )
            ),
            "timeout must name the stalled path: {error}"
        );
        assert!(
            elapsed >= super::super::PROBE_TIMEOUT
                && elapsed < super::super::PROBE_TIMEOUT + Duration::from_secs(5),
            "request exceeded its probe deadline: {elapsed:?}"
        );
        assert!(
            !marker.exists(),
            "workload executed before rejecting the policy"
        );
    }

    fn run_cases(backend: &str, provision: bool, name: &str) {
        if let Ok(stage) = std::env::var(STAGE_ENV) {
            let directory = PathBuf::from(std::env::var_os(DIRECTORY_ENV).unwrap());
            exercise_request(backend, provision, stage, &directory);
            return;
        }
        let module = module_path!().split_once("::").unwrap().1;
        for stage in ["parser", "object", "delegation"] {
            let directory = tempfile::tempdir().unwrap();
            let log = File::create(directory.path().join("child.log")).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("{module}::{name}"),
                    "--ignored",
                    "--nocapture",
                ])
                .env(STAGE_ENV, stage)
                .env(DIRECTORY_ENV, directory.path())
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap();
            let deadline = Instant::now() + WATCHDOG;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let output = std::fs::read_to_string(directory.path().join("child.log")).unwrap();
            assert!(
                status.is_some_and(|status| status.success()),
                "{backend} {stage} stalled-path rejection failed: {status:?}\n{output}"
            );
            assert!(
                output.contains("test result: ok. 1 passed;"),
                "{backend} {stage} did not execute its child regression:\n{output}"
            );
            assert!(
                !directory.path().join("workload-ran").exists(),
                "{backend} executed the workload before rejecting {stage}"
            );
        }
    }

    #[test]
    #[ignore = "runs in backend validation with an external watchdog"]
    #[cfg(target_os = "linux")]
    fn bubblewrap_launch_rejects_stalled_paths() {
        run_cases(
            "bubblewrap",
            false,
            "bubblewrap_launch_rejects_stalled_paths",
        );
    }

    #[test]
    #[ignore = "runs in backend validation with an external watchdog"]
    #[cfg(target_os = "linux")]
    fn lxc_launch_rejects_stalled_paths() {
        run_cases("lxc", false, "lxc_launch_rejects_stalled_paths");
    }

    #[test]
    #[ignore = "runs in backend validation with an external watchdog"]
    #[cfg(all(windows, feature = "wslc"))]
    fn wslc_launch_rejects_stalled_paths() {
        run_cases("wslc", false, "wslc_launch_rejects_stalled_paths");
    }

    #[test]
    #[ignore = "runs in backend validation with an external watchdog"]
    #[cfg(all(windows, feature = "wslc"))]
    fn wslc_provision_rejects_stalled_paths() {
        run_cases("wslc", true, "wslc_provision_rejects_stalled_paths");
    }
}
