use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::IoSlice;
#[cfg(target_arch = "aarch64")]
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{anyhow, Result};
use nix::errno::Errno;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_writev, RemoteIoVec};
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use procfs::process::Task;
use procfs::ProcError;
use retry::delay::Fixed;
use retry::Error::{self, Operation};
use retry::OperationResult;
use tracing::{error, info, instrument, trace, warn};
use Error::Internal;

// ---------------------------------------------------------------------------
// Architecture-specific register access helpers
// ---------------------------------------------------------------------------

/// Retrieve the register set of a traced thread.
///
/// On x86-64 we use `nix::sys::ptrace::getregs` which is available directly.
/// On aarch64 we fall back to the raw `PTRACE_GETREGSET` ptrace request with
/// `NT_PRSTATUS` because nix 0.21 does not expose `getregs` for that target.
#[cfg(target_arch = "x86_64")]
fn get_regs(pid: Pid) -> Result<libc::user_regs_struct> {
    Ok(ptrace::getregs(pid)?)
}

#[cfg(target_arch = "aarch64")]
fn get_regs(pid: Pid) -> Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET as libc::c_int,
            pid.as_raw(),
            libc::NT_PRSTATUS as usize as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(regs)
}

/// Write the register set back to a traced thread.
#[cfg(target_arch = "x86_64")]
fn set_regs(pid: Pid, regs: libc::user_regs_struct) -> Result<()> {
    Ok(ptrace::setregs(pid, regs)?)
}

#[cfg(target_arch = "aarch64")]
fn set_regs(pid: Pid, regs: libc::user_regs_struct) -> Result<()> {
    let mut regs = regs;
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET as libc::c_int,
            pid.as_raw(),
            libc::NT_PRSTATUS as usize as *mut libc::c_void,
            &mut iov as *mut libc::iovec as *mut libc::c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Return the program counter (instruction pointer) from a register snapshot.
#[cfg(target_arch = "x86_64")]
#[inline]
fn get_pc(regs: &libc::user_regs_struct) -> u64 {
    regs.rip
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn get_pc(regs: &libc::user_regs_struct) -> u64 {
    regs.pc
}

/// Update the program counter in a register snapshot.
#[cfg(target_arch = "x86_64")]
#[inline]
fn set_pc(regs: &mut libc::user_regs_struct, pc: u64) {
    regs.rip = pc;
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn set_pc(regs: &mut libc::user_regs_struct, pc: u64) {
    regs.pc = pc;
}

/// Read the syscall return value from a register snapshot.
#[cfg(target_arch = "x86_64")]
#[inline]
fn get_return_value(regs: &libc::user_regs_struct) -> u64 {
    regs.rax
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn get_return_value(regs: &libc::user_regs_struct) -> u64 {
    regs.regs[0]
}

/// Load syscall number and arguments into the register snapshot.
///
/// x86-64 Linux syscall ABI: syscall number in `rax`, args in
/// `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.
///
/// aarch64 Linux syscall ABI: syscall number in `x8`, args in
/// `x0`–`x5`.
#[cfg(target_arch = "x86_64")]
fn set_syscall_regs(regs: &mut libc::user_regs_struct, id: u64, args: &[u64]) -> Result<()> {
    regs.rax = id;
    for (index, arg) in args.iter().enumerate() {
        match index {
            0 => regs.rdi = *arg,
            1 => regs.rsi = *arg,
            2 => regs.rdx = *arg,
            3 => regs.r10 = *arg,
            4 => regs.r8 = *arg,
            5 => regs.r9 = *arg,
            _ => return Err(anyhow!("too many arguments for a syscall")),
        }
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn set_syscall_regs(regs: &mut libc::user_regs_struct, id: u64, args: &[u64]) -> Result<()> {
    regs.regs[8] = id;
    for (index, arg) in args.iter().enumerate() {
        if index < 6 {
            regs.regs[index] = *arg;
        } else {
            return Err(anyhow!("too many arguments for a syscall"));
        }
    }
    Ok(())
}

/// Syscall instruction encoded as a word for use with `PTRACE_POKETEXT`.
///
/// x86-64: `syscall` opcode = 0x0F 0x05 (2 bytes, fits in lowest bytes of an 8-byte word).
/// aarch64: `svc #0` = 0xD4000001 (4 bytes, little-endian).
#[cfg(target_arch = "x86_64")]
const SYSCALL_INST: usize = 0x050f;

#[cfg(target_arch = "aarch64")]
const SYSCALL_INST: usize = 0xd4000001;

/// Linux syscall numbers that vary between x86-64 and aarch64.
///
/// x86-64: https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
/// aarch64: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h
#[cfg(target_arch = "x86_64")]
mod syscall_nr {
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
    pub const CHDIR: u64 = 80;
}

#[cfg(target_arch = "aarch64")]
mod syscall_nr {
    pub const MMAP: u64 = 222;
    pub const MUNMAP: u64 = 215;
    pub const CHDIR: u64 = 49;
}

// ---------------------------------------------------------------------------

// There should be only one PtraceManager in one thread. But as we don't implement TLS
// , we cannot use thread-local variables safely.
#[derive(Debug, Default)]
pub struct PtraceManager {
    counter: RefCell<HashMap<i32, i32>>,
}

thread_local! {
    static PTRACE_MANAGER: PtraceManager = PtraceManager::default()
}

pub fn trace(pid: i32) -> Result<TracedProcess> {
    PTRACE_MANAGER.with(|pm| pm.trace(pid))
}

fn thread_is_gone(state: char) -> bool {
    // return true if the process is Zombie or Dead
    state == 'Z' || state == 'x' || state == 'X'
}

#[instrument]
fn attach_task(task: &Task) -> Result<()> {
    let pid = Pid::from_raw(task.tid);
    let process = procfs::process::Process::new(task.tid)?;

    trace!("attach task: {}", task.tid);
    match ptrace::attach(pid) {
        Err(errno)
            if errno == Errno::ESRCH
                || (errno == Errno::EPERM && thread_is_gone(process.stat().map(|s| s.state).unwrap_or('Z'))) =>
        {
            info!("task {} doesn't exist, maybe has stopped", task.tid)
        }
        Err(err) => {
            warn!("attach error: {:?}", err);
            return Err(err.into());
        }
        _ => {}
    }
    info!("attach task: {} successfully", task.tid);

    // TODO: check wait result
    match wait::waitpid(pid, Some(wait::WaitPidFlag::__WALL)) {
        Ok(status) => {
            info!("wait status: {:?}", status);
        }
        Err(err) => warn!("fail to wait for process({}): {:?}", pid, err),
    };

    Ok(())
}

impl PtraceManager {
    #[instrument(skip(self))]
    pub fn trace(&self, pid: i32) -> Result<TracedProcess> {
        let raw_pid = pid;
        let pid = Pid::from_raw(pid);

        let mut counter_ref = self.counter.borrow_mut();
        match counter_ref.get_mut(&raw_pid) {
            Some(count) => *count += 1,
            None => {
                trace!("stop {} successfully", pid);

                let mut iterations = 2;
                let mut traced_tasks = HashSet::<i32>::new();

                while iterations > 0 {
                    let mut new_threads_found = false;
                    let process = procfs::process::Process::new(raw_pid)?;
                    for task in process.tasks()?.flatten() {
                        if traced_tasks.contains(&task.tid) {
                            continue;
                        }

                        if let Ok(()) = attach_task(&task) {
                            trace!("newly traced task: {}", task.tid);
                            new_threads_found = true;
                            traced_tasks.insert(task.tid);
                        }
                    }

                    if !new_threads_found {
                        iterations -= 1;
                    }
                }

                info!("trace process: {} successfully", pid);
                counter_ref.insert(raw_pid, 1);
            }
        }

        Ok(TracedProcess { pid: raw_pid })
    }

    #[instrument(skip(self))]
    pub fn detach(&self, pid: i32) -> Result<()> {
        let mut counter_ref = self.counter.borrow_mut();
        match counter_ref.get_mut(&pid) {
            Some(count) => {
                *count -= 1;
                trace!("decrease counter to {}", *count);
                if *count < 1 {
                    counter_ref.remove(&pid);

                    info!("detach process: {}", pid);
                    if let Err(err) = retry::retry::<_, _, _, anyhow::Error, _>(
                        Fixed::from_millis(500).take(20),
                        || match procfs::process::Process::new(pid) {
                            Err(ProcError::NotFound(_)) => {
                                info!("process {} not found", pid);
                                OperationResult::Ok(())
                            }
                            Err(err) => {
                                warn!("fail to detach task: {}, retry", pid);
                                OperationResult::Retry(err.into())
                            }
                            Ok(process) => match process.tasks() {
                                Err(err) => OperationResult::Retry(err.into()),
                                Ok(tasks) => {
                                    for task in tasks.flatten() {
                                        match ptrace::detach(Pid::from_raw(task.tid), None) {
                                                Ok(()) => {
                                                    info!("successfully detached task: {}", task.tid);
                                                }
                                                Err(Errno::ESRCH) => trace!(
                                                    "task {} doesn't exist, maybe has stopped or not traced",
                                                    task.tid
                                                ),
                                                Err(err) => {
                                                    warn!("fail to detach: {:?}", err)
                                                },
                                            }
                                        trace!("detach task: {} successfully", task.tid);
                                    }
                                    info!("detach process: {} successfully", pid);
                                    OperationResult::Ok(())
                                }
                            },
                        },
                    ) {
                        warn!("fail to detach: {:?}", err);
                        match err {
                            Operation {
                                error: e,
                                total_delay: _,
                                tries: _,
                            } => return Err(e),
                            Internal(err) => error!("internal error: {:?}", err),
                        }
                    };
                }

                Ok(())
            }
            None => Err(anyhow::anyhow!("haven't traced this process")),
        }
    }
}

#[derive(Debug)]
pub struct TracedProcess {
    pub pid: i32,
}

impl Clone for TracedProcess {
    fn clone(&self) -> Self {
        // TODO: handler error here
        PTRACE_MANAGER.with(|pm| pm.trace(self.pid)).unwrap()
    }
}

impl TracedProcess {
    #[instrument]
    fn protect(&self) -> Result<ThreadGuard> {
        let regs = get_regs(Pid::from_raw(self.pid))?;

        let pc = get_pc(&regs);
        trace!("protecting regs: {:?}", regs);
        let rip_ins = ptrace::read(Pid::from_raw(self.pid), pc as *mut libc::c_void)?;

        let guard = ThreadGuard {
            tid: self.pid,
            regs,
            rip_ins,
        };
        Ok(guard)
    }

    #[instrument(skip(f))]
    fn with_protect<R, F: Fn(&Self) -> Result<R>>(&self, f: F) -> Result<R> {
        let guard = self.protect()?;

        let ret = f(self)?;

        drop(guard);

        Ok(ret)
    }

    #[instrument]
    fn syscall(&self, id: u64, args: &[u64]) -> Result<u64> {
        trace!("run syscall {} {:?}", id, args);

        self.with_protect(|thread| -> Result<u64> {
            let pid = Pid::from_raw(thread.pid);

            let mut regs = get_regs(pid)?;
            let cur_ins_ptr = get_pc(&regs);

            set_syscall_regs(&mut regs, id, args)?;
            trace!("setting regs for pid: {:?}, regs: {:?}", pid, regs);
            set_regs(pid, regs)?;

            // Write the architecture-specific syscall instruction at the current
            // program counter so the traced thread executes exactly one syscall.
            ptrace::write(
                    pid,
                    cur_ins_ptr as *mut libc::c_void,
                    SYSCALL_INST as libc::c_long,
                )?;
            ptrace::step(pid, None)?;

            loop {
                let status = wait::waitpid(pid, None)?;
                info!("wait status: {:?}", status);
                match status {
                    wait::WaitStatus::Stopped(_, Signal::SIGTRAP) => break,
                    _ => ptrace::step(pid, None)?,
                }
            }

            let regs = get_regs(pid)?;

            trace!("returned: {:?}", get_return_value(&regs));

            Ok(get_return_value(&regs))
        })
    }

    #[instrument]
    pub fn mmap(&self, length: u64, fd: u64) -> Result<u64> {
        let prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC;
        let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON;

        self.syscall(
            syscall_nr::MMAP,
            &[0, length, prot.bits() as u64, flags.bits() as u64, fd, 0],
        )
    }

    #[instrument]
    pub fn munmap(&self, addr: u64, len: u64) -> Result<u64> {
        self.syscall(syscall_nr::MUNMAP, &[addr, len])
    }

    #[instrument(skip(f))]
    pub fn with_mmap<R, F: Fn(&Self, u64) -> Result<R>>(&self, len: u64, f: F) -> Result<R> {
        let addr = self.mmap(len, 0)?;

        let ret = f(self, addr)?;

        self.munmap(addr, len)?;

        Ok(ret)
    }

    #[instrument]
    pub fn chdir<P: AsRef<Path> + std::fmt::Debug>(&self, filename: P) -> Result<()> {
        let filename = CString::new(filename.as_ref().as_os_str().as_bytes())?;
        let path = filename.as_bytes_with_nul();

        self.with_mmap(path.len() as u64, |process, addr| {
            process.write_mem(addr, path)?;

            self.syscall(syscall_nr::CHDIR, &[addr])?;
            Ok(())
        })
    }

    #[instrument]
    pub fn write_mem(&self, addr: u64, content: &[u8]) -> Result<()> {
        let pid = Pid::from_raw(self.pid);

        process_vm_writev(
            pid,
            &[IoSlice::new(content)],
            &[RemoteIoVec {
                base: addr as usize,
                len: content.len(),
            }],
        )?;

        Ok(())
    }

    #[instrument(skip(codes))]
    pub fn run_codes<F: Fn(u64) -> Result<(u64, Vec<u8>)>>(&self, codes: F) -> Result<()> {
        let pid = Pid::from_raw(self.pid);

        let regs = get_regs(pid)?;
        let (_, ins) = codes(get_pc(&regs))?; // generate codes to get length

        self.with_mmap(ins.len() as u64 + 16, |_, addr| {
            self.with_protect(|_| {
                let (offset, ins) = codes(addr)?; // generate codes

                let end_addr = addr + ins.len() as u64;
                trace!("write instructions to addr: {:X}-{:X}", addr, end_addr);
                self.write_mem(addr, &ins)?;

                let mut regs = get_regs(pid)?;
                trace!("modify rip to addr: {:X}", addr + offset);
                set_pc(&mut regs, addr + offset);
                set_regs(pid, regs)?;

                let regs = get_regs(pid)?;
                info!("current registers: {:?}", regs);

                loop {
                    info!("run instructions");
                    ptrace::cont(pid, None)?;

                    info!("wait for pid: {:?}", pid);
                    let status = wait::waitpid(pid, None)?;
                    info!("wait status: {:?}", status);

                    use nix::sys::signal::SIGTRAP;
                    let regs = get_regs(pid)?;

                    info!("current registers: {:?}", regs);
                    match status {
                        wait::WaitStatus::Stopped(_, SIGTRAP) => {
                            break;
                        }
                        _ => info!("continue running replacers"),
                    }
                }
                Ok(())
            })
        })
    }
}

impl Drop for TracedProcess {
    fn drop(&mut self) {
        trace!("dropping traced process: {}", self.pid);

        if let Err(err) = PTRACE_MANAGER.with(|pm| pm.detach(self.pid)) {
            info!(
                "detaching process {} failed with error: {:?}",
                self.pid, err
            )
        }
    }
}

#[derive(Debug)]
struct ThreadGuard {
    tid: i32,
    regs: libc::user_regs_struct,
    rip_ins: i64,
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        let pid = Pid::from_raw(self.tid);
        ptrace::write(
                pid,
                get_pc(&self.regs) as *mut libc::c_void,
                self.rip_ins,
            )
            .unwrap();
        set_regs(pid, self.regs).unwrap();
    }
}
