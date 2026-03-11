use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use itertools::Itertools;
use procfs::process::FDTarget;
use tracing::{error, info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Clone, Copy)]
#[repr(packed)]
#[repr(C)]
struct ReplaceCase {
    fd: u64,
    new_path_offset: u64,
}

impl ReplaceCase {
    pub fn new(fd: u64, new_path_offset: u64) -> ReplaceCase {
        ReplaceCase {
            fd,
            new_path_offset,
        }
    }
}

struct ProcessAccessorBuilder {
    cases: Vec<ReplaceCase>,
    new_paths: Cursor<Vec<u8>>,
}

impl ProcessAccessorBuilder {
    pub fn new() -> ProcessAccessorBuilder {
        ProcessAccessorBuilder {
            cases: Vec::new(),
            new_paths: Cursor::new(Vec::new()),
        }
    }

    pub fn build(self, process: ptrace::TracedProcess) -> Result<ProcessAccessor> {
        Ok(ProcessAccessor {
            process,

            cases: self.cases,
            new_paths: self.new_paths,
        })
    }

    pub fn push_case(&mut self, fd: u64, new_path: PathBuf) -> anyhow::Result<()> {
        info!("push case fd: {}, new_path: {}", fd, new_path.display());

        let mut new_path = new_path
            .to_str()
            .ok_or(anyhow!("fd contains non-UTF-8 character"))?
            .as_bytes()
            .to_vec();

        new_path.push(0);

        let offset = self.new_paths.position();
        self.new_paths.write_all(new_path.as_slice())?;

        self.cases.push(ReplaceCase::new(fd, offset));

        Ok(())
    }
}

impl FromIterator<(u64, PathBuf)> for ProcessAccessorBuilder {
    fn from_iter<T: IntoIterator<Item = (u64, PathBuf)>>(iter: T) -> Self {
        let mut builder = Self::new();
        for (fd, path) in iter {
            if let Err(err) = builder.push_case(fd, path) {
                error!("fail to write to AccessorBuilder. Error: {:?}", err)
            }
        }

        builder
    }
}

struct ProcessAccessor {
    process: ptrace::TracedProcess,

    cases: Vec<ReplaceCase>,
    new_paths: Cursor<Vec<u8>>,
}

impl Debug for ProcessAccessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.process.fmt(f)
    }
}

impl ProcessAccessor {
    pub fn run(&mut self) -> anyhow::Result<()> {
        self.new_paths.set_position(0);

        let mut new_paths = Vec::new();
        self.new_paths.read_to_end(&mut new_paths)?;

        let (cases_ptr, length, _) = self.cases.clone().into_raw_parts();
        let size = length * std::mem::size_of::<ReplaceCase>();
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr as *mut u8, size) };

        self.process
            .run_codes(|addr| build_fd_replace_code(addr, cases, &new_paths))?;

        trace!("reopen successfully");
        Ok(())
    }
}

/// Generate the JIT trampoline that re-opens every file descriptor listed in
/// `cases` and points it at the corresponding entry in `new_paths`.
///
/// The function is split into one implementation per supported architecture so
/// that only the relevant dynasm assembler type is referenced at compile time.
#[cfg(target_arch = "x86_64")]
fn build_fd_replace_code(
    addr: u64,
    cases: &[u8],
    new_paths: &[u8],
) -> anyhow::Result<(u64, Vec<u8>)> {
    let mut vec_rt = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(addr as usize);
    dynasm!(vec_rt
        ; .arch x64
        ; ->cases:
        ; .bytes cases
        ; ->cases_length:
        ; .qword cases.len() as i64
        ; ->new_paths:
        ; .bytes new_paths
        ; nop
        ; nop
    );

    trace!("static bytes placed");
    let replace = vec_rt.offset();
    dynasm!(vec_rt
        ; .arch x64
        // set r15 to 0
        ; xor r15, r15
        ; lea r14, [-> cases]

        ; jmp ->end
        ; ->start:
        // fcntl(fd, F_GETFL, 0) – retrieve open file status flags
        ; mov rax, 0x48
        ; mov rdi, QWORD [r14+r15] // fd
        ; mov rsi, 0x3
        ; mov rdx, 0x0
        ; syscall
        ; mov rsi, rax
        // open(path, flags, 0)
        ; mov rax, 0x2
        ; lea rdi, [-> new_paths]
        ; add rdi, QWORD [r14+r15+8] // path
        ; mov rdx, 0x0
        ; syscall
        ; mov r12, rax // store newly opened fd in r12
        // lseek(old_fd, 0, SEEK_CUR) – get current file position
        ; mov rax, 0x8
        ; mov rdi, QWORD [r14+r15] // fd
        ; mov rsi, 0
        ; mov rdx, libc::SEEK_CUR
        ; syscall
        ; mov rdi, r12
        ; mov rsi, rax
        // lseek(new_fd, pos, SEEK_SET) – set same position on new fd
        ; mov rax, 0x8
        ; mov rdx, libc::SEEK_SET
        ; syscall
        // dup2(new_fd, old_fd)
        ; mov rax, 0x21
        ; mov rdi, r12
        ; mov rsi, QWORD [r14+r15] // fd
        ; syscall
        // close(new_fd)
        ; mov rax, 0x3
        ; mov rdi, r12
        ; syscall

        ; add r15, std::mem::size_of::<ReplaceCase>() as i32
        ; ->end:
        ; mov r13, QWORD [->cases_length]
        ; cmp r15, r13
        ; jb ->start

        ; int3
    );

    let instructions = vec_rt.finalize()?;
    Ok((replace.0 as u64, instructions))
}

/// aarch64 version of the fd-replacement trampoline.
///
/// Syscall numbers (aarch64 Linux):
///   fcntl   = 25   openat  = 56   lseek   = 62   dup3    = 24   close   = 57
///
/// Note: aarch64 has no `open` syscall; `openat(AT_FDCWD, …)` is used instead.
///       `dup2` is likewise absent; `dup3` with flags=0 is the equivalent.
#[cfg(target_arch = "aarch64")]
fn build_fd_replace_code(
    addr: u64,
    cases: &[u8],
    new_paths: &[u8],
) -> anyhow::Result<(u64, Vec<u8>)> {
    let mut vec_rt =
        dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(addr as usize);
    dynasm!(vec_rt
        ; .arch aarch64
        ; ->cases:
        ; .bytes cases
        ; ->cases_length:
        ; .qword cases.len() as i64
        ; ->new_paths:
        ; .bytes new_paths
        ; nop
        ; nop
    );

    trace!("static bytes placed");
    let replace = vec_rt.offset();
    dynasm!(vec_rt
        ; .arch aarch64
        // x15 = 0 (byte offset / loop counter into cases array)
        ; mov x15, xzr
        // x14 = base address of cases table
        ; adr x14, ->cases

        ; b ->end
        ; ->start:
        // x16 = pointer to current ReplaceCase entry
        ; add x16, x14, x15

        // fcntl(fd=cases[i].fd, cmd=F_GETFL=3, arg=0)
        ; ldr x0, [x16]         // x0 = fd
        ; mov x1, 3             // F_GETFL = 3
        ; mov x2, xzr           // arg = 0
        ; mov x8, 25            // x8 = fcntl syscall number (25 on aarch64)
        ; svc 0
        ; mov x13, x0           // x13 = flags (save)

        // openat(AT_FDCWD=-100, path, flags, mode=0)
        ; mov x0, xzr
        ; sub x0, x0, 100       // x0 = -100 = AT_FDCWD
        ; adr x1, ->new_paths   // x1 = base of new_paths
        ; ldr x9, [x16, 8]      // x9 = new_path_offset (ReplaceCase+8)
        ; add x1, x1, x9        // x1 = &new_paths[new_path_offset]
        ; mov x2, x13           // x2 = flags from fcntl
        ; mov x3, xzr           // x3 = mode = 0
        ; mov x8, 56            // x8 = openat syscall number (56 on aarch64)
        ; svc 0
        ; mov x11, x0           // x11 = new fd (save)

        // lseek(old_fd, 0, SEEK_CUR=1) – get current file position
        ; ldr x0, [x16]         // x0 = old fd
        ; mov x1, xzr           // x1 = offset = 0
        ; mov x2, 1             // SEEK_CUR = 1
        ; mov x8, 62            // x8 = lseek syscall number (62 on aarch64)
        ; svc 0
        ; mov x10, x0           // x10 = current position (save)

        // lseek(new_fd, position, SEEK_SET=0) – seek new fd to same position
        ; mov x0, x11           // x0 = new fd
        ; mov x1, x10           // x1 = position
        ; mov x2, xzr           // x2 = SEEK_SET = 0
        ; mov x8, 62            // lseek
        ; svc 0

        // dup3(new_fd, old_fd, 0) – aarch64 equivalent of dup2(new_fd, old_fd)
        ; mov x0, x11           // x0 = new fd (oldfd arg)
        ; ldr x1, [x16]         // x1 = old fd (newfd arg)
        ; mov x2, xzr           // x2 = flags = 0
        ; mov x8, 24            // x8 = dup3 syscall number (24 on aarch64)
        ; svc 0

        // close(new_fd)
        ; mov x0, x11           // x0 = new fd
        ; mov x8, 57            // x8 = close syscall number (57 on aarch64)
        ; svc 0

        // Advance loop counter by sizeof(ReplaceCase)
        ; add x15, x15, std::mem::size_of::<ReplaceCase>() as u32
        ; ->end:
        ; adr x12, ->cases_length
        ; ldr x13, [x12]        // x13 = total byte length of cases
        ; cmp x15, x13
        ; b.lo ->start

        ; brk 0                 // triggers SIGTRAP – execution complete
    );

    let instructions = vec_rt.finalize()?;
    Ok((replace.0 as u64, instructions))
}

pub struct FdReplacer {
    processes: HashMap<i32, ProcessAccessor>,
}

impl FdReplacer {
    pub fn prepare<P1: AsRef<Path>, P2: AsRef<Path>>(
        detect_path: P1,
        new_path: P2,
    ) -> Result<FdReplacer> {
        info!("preparing fd replacer");

        let detect_path = detect_path.as_ref();
        let new_path = new_path.as_ref();

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;

                let traced_process = match ptrace::trace(pid) {
                    Ok(p) => p,
                    Err(err) => {
                        error!("fail to trace process: {} {}", pid, err);
                        return None;
                    }
                };
                let fd = process.fd().ok()?;

                Some((traced_process, fd))
            })
            .flat_map(|(process, fd)| {
                fd.into_iter()
                    .filter_map(|entry| match entry.target {
                        FDTarget::Path(path) => Some((entry.fd as u64, path)),
                        _ => None,
                    })
                    .filter(|(_, path)| path.starts_with(detect_path))
                    .filter_map(move |(fd, path)| {
                        trace!("replace fd({}): {}", fd, path.display());
                        let stripped_path = path.strip_prefix(&detect_path).ok()?;
                        Some((process.clone(), (fd, new_path.join(stripped_path))))
                    })
            })
            .group_by(|(process, _)| process.pid)
            .into_iter()
            .filter_map(|(pid, group)| Some((ptrace::trace(pid).ok()?, group)))
            .map(|(process, group)| (process, group.map(|(_, group)| group)))
            .filter_map(|(process, group)| {
                let pid = process.pid;
                match group.collect::<ProcessAccessorBuilder>().build(process) {
                    Ok(accessor) => Some((pid, accessor)),
                    Err(err) => {
                        error!("fail to build accessor: {:?}", err);
                        None
                    }
                }
            })
            .collect();

        Ok(FdReplacer { processes })
    }
}

impl Replacer for FdReplacer {
    fn run(&mut self) -> Result<()> {
        info!("running fd replacer");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.run()?;
        }

        Ok(())
    }
}
