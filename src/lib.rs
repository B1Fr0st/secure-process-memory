use sysinfo::System;
use std::{fs, io::{self, Read, Seek}, process::Command};


pub fn return_pid(target:&str) -> Option<u32> {
    let mut target_process_id = None;
    let mut sys = System::new_all();
    sys.refresh_all();

    use std::ffi::OsStr;
    for (pid, process) in sys.processes() {
        let cmdline = process.cmd().join(OsStr::new(" "));
        if cmdline.to_string_lossy().contains(target)
        {
            //we want the parent process, children have a higher process id than their parent
            if target_process_id.is_none() || target_process_id.unwrap() > pid.as_u32() {
                target_process_id = Some(pid.as_u32());
            }
        }
    }

    target_process_id
}

pub fn protect_process() -> bool {
    let status = Command::new("sudo")
        .arg("mount")
        .arg("-o")
        .arg("remount,rw,hidepid=2")
        .arg("/proc")
        .status()
        .expect("failed to execute process");

    if !status.success() {
        return false;
    }

    let status = Command::new("sudo")
        .arg("sysctl")
        .arg("-w")
        .arg("kernel.yama.ptrace_scope=2")
        .status()
        .expect("Failed to set ptrace_scope");

    if !status.success() {
        return false;
    }
    
    check_protection_status()
}

fn check_protection_status() -> bool {
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            if line.contains(" /proc ") {
                if line.contains("hidepid=invisible") {
                    return true;
                }
            }
        }
    }
    false
}

pub fn read_memory(pid: u32, addr: usize, size:usize) -> io::Result<Vec<u8>>{
    let mut procmem = fs::File::open(format!("/proc/{}/mem", pid))?;
    procmem.seek(io::SeekFrom::Start(addr as u64))?;
    let mut buf = vec![0;size];
    procmem.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read<T>(pid: u32, addr: usize) -> io::Result<Vec<u8>> {
    read_memory(pid, addr, size_of::<T>())
}