use anyhow::Result;
use procfs::process::{self, Process};
use procfs::ProcError;

pub fn all_processes() -> Result<impl Iterator<Item = Process>> {
    Ok(process::all_processes()?
        .filter_map(|r: std::result::Result<Process, ProcError>| r.ok())
        .filter(|process| -> bool {
            if let Ok(cmdline) = process.cmdline() {
                !cmdline.iter().any(|s| s.contains("toda"))
            } else {
                true
            }
        }))
}
