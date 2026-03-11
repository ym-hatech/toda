use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use itertools::Itertools;
use nix::sys::mman::{MapFlags, ProtFlags};
use procfs::process::MMapPath;
use tracing::{error, info, trace};

use super::utils::all_processes;
use super::{ptrace, Replacer};

#[derive(Clone, Debug)]
struct ReplaceCase {
    pub memory_addr: u64,
    pub length: u64,
    pub prot: u64,
    pub flags: u64,
    pub path: PathBuf,
    pub offset: u64,
}

#[derive(Clone, Copy)]
#[repr(packed)]
#[repr(C)]
struct RawReplaceCase {
    memory_addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    new_path_offset: u64,
    offset: u64,
}

impl RawReplaceCase {
    pub fn new(
        memory_addr: u64,
        length: u64,
        prot: u64,
        flags: u64,
        new_path_offset: u64,
        offset: u64,
    ) -> RawReplaceCase {
        RawReplaceCase {
            memory_addr,
            length,
            prot,
            flags,
            new_path_offset,
            offset,
        }
    }
}

// TODO: encapsulate this struct for fd replacer and mmap replacer
struct ProcessAccessorBuilder {
    cases: Vec<RawReplaceCase>,
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

    pub fn push_case(
        &mut self,
        memory_addr: u64,
        length: u64,
        prot: u64,
        flags: u64,
        new_path: PathBuf,
        offset: u64,
    ) -> anyhow::Result<()> {
        info!("push case");

        let mut new_path = new_path
            .to_str()
            .ok_or(anyhow!("fd contains non-UTF-8 character"))?
            .as_bytes()
            .to_vec();

        new_path.push(0);

        let new_path_offset = self.new_paths.position();
        self.new_paths.write_all(new_path.as_slice())?;

        self.cases.push(RawReplaceCase::new(
            memory_addr,
            length,
            prot,
            flags,
            new_path_offset,
            offset,
        ));

        Ok(())
    }
}

impl FromIterator<ReplaceCase> for ProcessAccessorBuilder {
    fn from_iter<T: IntoIterator<Item = ReplaceCase>>(iter: T) -> Self {
        let mut builder = Self::new();
        for case in iter {
            if let Err(err) = builder.push_case(
                case.memory_addr,
                case.length,
                case.prot,
                case.flags,
                case.path,
                case.offset,
            ) {
                error!("fail to write to AccessorBuilder. Error: {:?}", err)
            }
        }

        builder
    }
}

struct ProcessAccessor {
    process: ptrace::TracedProcess,

    cases: Vec<RawReplaceCase>,
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
        let size = length * std::mem::size_of::<RawReplaceCase>();
        let cases = unsafe { std::slice::from_raw_parts(cases_ptr as *mut u8, size) };

        self.process
            .run_codes(|addr| build_mmap_replace_code(addr, cases, &new_paths))?;

        trace!("reopen successfully");
        Ok(())
    }
}

/// Generate the JIT trampoline that unmaps every region listed in `cases` and
/// remaps it from the corresponding file in `new_paths`.
#[cfg(target_arch = "x86_64")]
fn build_mmap_replace_code(
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
        // munmap(addr, length)
        ; mov rax, 0x0B
        ; mov rdi, QWORD [r14+r15] // addr
        ; mov rsi, QWORD [r14+r15+8] // length
        ; mov rdx, 0x0
        ; push rdi
        ; syscall
        // open(path, O_RDWR)
        ; mov rax, 0x2

        ; lea rdi, [-> new_paths]
        ; add r15, 8 * 4 // set r15 to point to path
        ; add rdi, QWORD [r14+r15] // path
        ; sub r15, 8 * 4

        ; mov rsi, libc::O_RDWR
        ; mov rdx, 0x0
        ; syscall
        ; pop rdi // addr
        ; push rax
        ; mov r8, rax // fd
        // mmap(addr, length, prot, flags, fd, offset)
        ; mov rax, 0x9
        ; add r15, 8
        ; mov rsi, QWORD [r14+r15] // length
        ; add r15, 8
        ; mov rdx, QWORD [r14+r15] // prot
        ; add r15, 8
        ; mov r10, QWORD [r14+r15] // flags
        ; add r15, 16
        ; mov r9, QWORD [r14+r15] // offset
        ; syscall
        ; sub r15, 8 * 5
        // close(fd)
        ; mov rax, 0x3
        ; pop rdi
        ; syscall

        ; add r15, std::mem::size_of::<RawReplaceCase>() as i32
        ; ->end:
        ; mov r13, QWORD [->cases_length]
        ; cmp r15, r13
        ; jb ->start

        ; int3
    );

    let instructions = vec_rt.finalize()?;
    Ok((replace.0 as u64, instructions))
}

/// aarch64 version of the mmap-replacement trampoline.
///
/// Syscall numbers (aarch64 Linux):
///   munmap  = 215   openat  = 56   mmap    = 222   close   = 57
///
/// RawReplaceCase layout (all u64, 8 bytes each):
///   +0  memory_addr   +8  length   +16  prot   +24  flags   +32  new_path_offset   +40  offset
#[cfg(target_arch = "aarch64")]
fn build_mmap_replace_code(
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
        // x15 = 0 (byte offset / loop counter)
        ; mov x15, xzr
        // x14 = base address of cases table
        ; adr x14, ->cases

        ; b ->end
        ; ->start:
        // x16 = pointer to current RawReplaceCase entry
        ; add x16, x14, x15

        // munmap(addr=cases[i].memory_addr, length=cases[i].length)
        ; ldr x0, [x16]          // x0 = memory_addr
        ; ldr x1, [x16, 8]       // x1 = length
        ; mov x8, 215            // x8 = munmap syscall number (215 on aarch64)
        ; svc 0
        // Save memory_addr for mmap fixed-address hint
        ; ldr x17, [x16]         // x17 = memory_addr

        // openat(AT_FDCWD=-100, path, O_RDWR, 0)
        ; mov x0, xzr
        ; sub x0, x0, 100        // x0 = AT_FDCWD = -100
        ; adr x1, ->new_paths    // x1 = base of new_paths
        ; ldr x9, [x16, 32]      // x9 = new_path_offset (RawReplaceCase+32)
        ; add x1, x1, x9         // x1 = &new_paths[new_path_offset]
        ; mov x2, libc::O_RDWR   // x2 = O_RDWR
        ; mov x3, xzr            // x3 = mode = 0
        ; mov x8, 56             // x8 = openat syscall number (56 on aarch64)
        ; svc 0
        ; mov x11, x0            // x11 = fd (save)

        // mmap(addr=memory_addr, length, prot, flags, fd, offset)
        ; mov x0, x17            // x0 = memory_addr (hint/fixed address)
        ; ldr x1, [x16, 8]       // x1 = length
        ; ldr x2, [x16, 16]      // x2 = prot
        ; ldr x3, [x16, 24]      // x3 = flags
        ; mov x4, x11            // x4 = fd
        ; ldr x5, [x16, 40]      // x5 = offset
        ; mov x8, 222            // x8 = mmap syscall number (222 on aarch64)
        ; svc 0

        // close(fd)
        ; mov x0, x11            // x0 = fd
        ; mov x8, 57             // x8 = close syscall number (57 on aarch64)
        ; svc 0

        // Advance loop counter by sizeof(RawReplaceCase)
        ; add x15, x15, std::mem::size_of::<RawReplaceCase>() as u32
        ; ->end:
        ; adr x12, ->cases_length
        ; ldr x13, [x12]         // x13 = total byte length of cases
        ; cmp x15, x13
        ; b.lo ->start

        ; brk 0                  // triggers SIGTRAP – execution complete
    );

    let instructions = vec_rt.finalize()?;
    Ok((replace.0 as u64, instructions))
}

fn get_prot_and_flags_from_perms<S: AsRef<str>>(perms: S) -> (u64, u64) {
    let bytes = perms.as_ref().as_bytes();
    let mut prot = ProtFlags::empty();
    let mut flags = MapFlags::MAP_PRIVATE;

    if bytes[0] == b'r' {
        prot |= ProtFlags::PROT_READ
    }
    if bytes[1] == b'w' {
        prot |= ProtFlags::PROT_WRITE
    }
    if bytes[2] == b'x' {
        prot |= ProtFlags::PROT_EXEC
    }
    if bytes[3] == b's' {
        flags = MapFlags::MAP_SHARED;
    }

    trace!(
        "perms: {}, prot: {:?}, flags: {:?}",
        perms.as_ref(),
        prot,
        flags
    );
    (prot.bits() as u64, flags.bits() as u64)
}

pub struct MmapReplacer {
    processes: HashMap<i32, ProcessAccessor>,
}

impl MmapReplacer {
    pub fn prepare<P1: AsRef<Path>, P2: AsRef<Path>>(
        detect_path: P1,
        new_path: P2,
    ) -> Result<MmapReplacer> {
        info!("preparing mmap replacer");

        let detect_path = detect_path.as_ref();
        let new_path = new_path.as_ref();

        let processes = all_processes()?
            .filter_map(|process| -> Option<_> {
                let pid = process.pid;

                let traced_process = ptrace::trace(pid).ok()?;
                let maps = process.maps().ok()?;

                Some((traced_process, maps))
            })
            .flat_map(|(process, maps)| {
                maps.into_iter()
                    .filter_map(move |entry| {
                        match entry.pathname {
                            MMapPath::Path(path) => {
                                let (start_address, end_address) = entry.address;
                                let length = end_address - start_address;
                                let (prot, flags) = get_prot_and_flags_from_perms(entry.perms);
                                // TODO: extract permission from perms

                                let case = ReplaceCase {
                                    memory_addr: start_address,
                                    length,
                                    prot,
                                    flags,
                                    path,
                                    offset: entry.offset,
                                };
                                Some((process.clone(), case))
                            }
                            _ => None,
                        }
                    })
                    .filter(|(_, case)| case.path.starts_with(detect_path))
                    .filter_map(|(process, mut case)| {
                        let stripped_path = case.path.strip_prefix(&detect_path).ok()?;
                        case.path = new_path.join(stripped_path);
                        Some((process, case))
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

        Ok(MmapReplacer { processes })
    }
}

impl Replacer for MmapReplacer {
    fn run(&mut self) -> Result<()> {
        info!("running mmap replacer");
        for (_, accessor) in self.processes.iter_mut() {
            accessor.run()?;
        }

        Ok(())
    }
}
