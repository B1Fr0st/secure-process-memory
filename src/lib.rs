#[cfg(target_os = "linux")]
mod platform {
    use std::{fs, process::Command, io::{self, Read, Seek, SeekFrom, Write}, mem::MaybeUninit, ptr};
    use sysinfo::System;

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


    #[derive(Debug)]
    pub enum ProcessCreationError{
        FailedToProtectProcess,
        NotSudo,
        FailedToGetMemFile
    }

    #[derive(Debug)]
    pub struct Process{
        pub pid: u32,
        file: fs::File,
    }

    impl Process{
        pub fn new(pid:u32) -> Result<Self,ProcessCreationError>{
            if unsafe{libc::geteuid()} != 0{
                return Err(ProcessCreationError::NotSudo);
            }
            if protect_process() == false {
                return Err(ProcessCreationError::FailedToProtectProcess);
            }
            let file = if let Ok(res) = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{}/mem", pid))
                {res} else {return Err(ProcessCreationError::FailedToGetMemFile);};
            Ok(Self {
                pid,
                file
            })
        }
        pub fn unprotected_new(pid:u32) -> Result<Self,ProcessCreationError>{
            if unsafe{libc::geteuid()} != 0{
                return Err(ProcessCreationError::NotSudo);
            }
            let file = if let Ok(res) = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{}/mem", pid))
                {res} else {return Err(ProcessCreationError::FailedToGetMemFile);};
            Ok(Self {
                pid,
                file
            })
        }
        /// Read raw memory from a process
        pub fn read_memory(&mut self, addr: usize, size: usize) -> io::Result<Vec<u8>> {
            self.file.seek(SeekFrom::Start(addr as u64))?;
            let mut buf = vec![0; size];
            self.file.read_exact(&mut buf)?;
            Ok(buf)
        }

        /// Read a typed value from another process's memory
        pub fn read<T: Copy>(&mut self, addr: usize) -> io::Result<T> {
            let bytes = self.read_memory(addr, size_of::<T>())?;

            if bytes.len() != size_of::<T>() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Failed to read enough bytes"));
            }

            let mut value = MaybeUninit::<T>::uninit();
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    value.as_mut_ptr() as *mut u8,
                    size_of::<T>(),
                );
                Ok(value.assume_init())
            }
        }

        /// Write raw memory to a process
        pub fn write_memory(&mut self, addr: usize, data: &[u8]) -> io::Result<()> {
            self.file.seek(SeekFrom::Start(addr as u64))?;
            self.file.write_all(data)?;
            Ok(())
        }

        /// Write a typed value to another process's memory
        pub fn write<T: Copy>(&mut self, addr: usize, value: &T) -> io::Result<()> {
            let data = unsafe {
                std::slice::from_raw_parts(
                    (value as *const T) as *const u8,
                    size_of::<T>(),
                )
            };
            self.write_memory(addr, data)
        }
    }
}

#[cfg(target_os="windows")]
mod platform {
    use std::io::{self, Error};
    use std::mem::MaybeUninit;
    use std::os::raw::c_void;
    use std::ptr;
    use windows::{
        Win32::Foundation::{CloseHandle, HANDLE},
        Win32::System::Diagnostics::{
            ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, 
            PROCESSENTRY32W, TH32CS_SNAPPROCESS},
            Debug::{ReadProcessMemory,WriteProcessMemory}
        },
        Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    };


     pub fn return_pid(target:&str) -> Option<u32> {
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };

        let mut process = None;
        
        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                // Convert the wide string to a regular string for comparison
                let process_name = {
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    String::from_utf16_lossy(&entry.szExeFile[..len])
                };

                if process_name.to_lowercase() == target {
                    process = Some(entry.th32ProcessID);
                }

                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        unsafe { CloseHandle(snapshot).ok()? };

        process
    }




    #[derive(Debug)]
    pub enum ProcessCreationError{
        FailedToGetProcess
    }

    #[derive(Debug)]
    pub struct Process{
        pub process_handle: HANDLE,
    }
    impl Process{
        pub fn new(pid:u32) -> Result<Self,ProcessCreationError>{
            let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) };
            match process_handle {
                Ok(process_handle) =>{
                    Ok(
                Self {
                    process_handle
                }
            )
                },
                Err(_) => {
                    Err(ProcessCreationError::FailedToGetProcess)
                }
            }
        }
        /// Read raw memory from a process
        pub fn read_memory(&mut self, addr: usize, size: usize) -> io::Result<Vec<u8>> {
            let mut buf = vec![0; size];
            let mut bytes_read = 0;
            if unsafe {
                ReadProcessMemory(
                    self.process_handle,
                    addr as *const c_void,
                    buf.as_mut_ptr().cast(),
                    size,
                    Some(&mut bytes_read)
                )
            }.is_err() || bytes_read != size {
                Err(Error::last_os_error())
            } else {
                Ok(buf)
            }
        }

        /// Read a typed value from another process's memory
        pub fn read<T: Copy>(&mut self, addr: usize) -> io::Result<T> {
            let bytes = self.read_memory(addr, size_of::<T>())?;

            if bytes.len() != size_of::<T>() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Failed to read enough bytes"));
            }

            let mut value = MaybeUninit::<T>::uninit();
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    value.as_mut_ptr() as *mut u8,
                    size_of::<T>(),
                );
                Ok(value.assume_init())
            }
        }

        /// Write raw memory to a process
        pub fn write_memory(&mut self, addr: usize, data: &[u8]) -> io::Result<()> {
            let mut bytes_written = 0;
            if unsafe {
                WriteProcessMemory(
                    self.process_handle,
                    addr as *const c_void,
                    data.as_ptr().cast(),
                    data.len(),
                    Some(&mut bytes_written)
                )
            }.is_err() || bytes_written != data.len() {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Write a typed value to another process's memory
        pub fn write<T: Copy>(&mut self, addr: usize, value: &T) -> io::Result<()> {
            let data = unsafe {
                std::slice::from_raw_parts(
                    (value as *const T) as *const u8,
                    size_of::<T>(),
                )
            };
            self.write_memory(addr, data)
        }
    }
}

#[cfg(any(target_os="windows",target_os="linux"))]
pub use platform::*;