//! Windows Job Object containment (doc appendix A.1).
//!
//! A launched work app is assigned to a Job Object created with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so the whole process tree dies with the daemon-held
//! handle and can be enumerated as a unit. This is the user-mode process-supervision primitive:
//! it contains and reconciles the work zone with the tree the OS actually holds, short of the
//! kernel `PsSetCreateProcessNotifyRoutineEx2` membership-at-birth guarantee (which needs the
//! signed driver).

#![allow(unsafe_code)]

use std::ffi::c_void;

use clave_platform::{PResult, PlatformError, ProcessContainment};
use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, QueryInformationJobObject, SetInformationJobObject,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

/// The maximum number of process ids read back in a single `contained_pids` query.
const MAX_PIDS: usize = 1024;

pub struct ContainmentJob {
    handle: HANDLE,
}

// A job handle is safe to use from any thread; the raw `HANDLE` pointer is what makes the
// compiler conservative. The daemon shares one job across its launcher and supervisor threads.
unsafe impl Send for ContainmentJob {}
unsafe impl Sync for ContainmentJob {}

impl ContainmentJob {
    pub fn new() -> PResult<Self> {
        unsafe {
            let handle = CreateJobObjectW(None, None).map_err(io)?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(io)?;
            Ok(Self { handle })
        }
    }
}

impl ProcessContainment for ContainmentJob {
    fn contain(&self, pid: u32) -> PResult<()> {
        unsafe {
            let proc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid).map_err(io)?;
            let assigned = AssignProcessToJobObject(self.handle, proc);
            let _ = CloseHandle(proc);
            assigned.map_err(io)
        }
    }

    fn contained_pids(&self) -> Vec<u32> {
        unsafe {
            let mut buf = vec![
                0u8;
                std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
                    + MAX_PIDS * std::mem::size_of::<usize>()
            ];
            if QueryInformationJobObject(
                self.handle,
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                None,
            )
            .is_err()
            {
                return Vec::new();
            }

            let list = &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST);
            let count = (list.NumberOfProcessIdsInList as usize).min(MAX_PIDS);
            let ids = list.ProcessIdList.as_ptr();
            (0..count).map(|i| *ids.add(i) as u32).collect()
        }
    }
}

impl Drop for ContainmentJob {
    fn drop(&mut self) {
        // Closing the last handle terminates every process still in the job.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn io(e: windows::core::Error) -> PlatformError {
    PlatformError::Io(e.message())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn contains_a_spawned_process_and_reports_it() {
        let job = ContainmentJob::new().expect("create job");

        // A long-lived, headless child we can assign and then kill by dropping the job.
        let mut child = Command::new("cmd.exe")
            .args(["/c", "pause"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd");
        let pid = child.id();

        job.contain(pid).expect("assign to job");
        assert!(
            job.contained_pids().contains(&pid),
            "the assigned pid must appear in the job's process list"
        );

        // Dropping the job closes the handle; kill-on-close terminates the child.
        drop(job);
        let _ = child.wait();
    }

    #[test]
    fn an_empty_job_reports_no_pids() {
        let job = ContainmentJob::new().expect("create job");
        assert!(job.contained_pids().is_empty());
    }
}
