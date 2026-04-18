use crate::Connection;
use std::collections::HashMap;

pub fn enrich_cmdline(conns: &mut [Connection]) {
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        if let Some(cmdline) = macos_cmdline(pid) {
            c.cmdline = Some(cmdline);
        }
    }
}

fn macos_cmdline(pid: u32) -> Option<String> {
    use std::ptr;
    unsafe {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let mut size = 0usize;
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        buf.truncate(size);
        if buf.len() < 4 {
            return None;
        }
        // First 4 bytes: argc (native endian), then exec path, then argv[0..argc]
        let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let mut pos = 4;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1; // skip exec path
        }
        while pos < buf.len() && buf[pos] == 0 {
            pos += 1; // skip null padding
        }
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            if pos >= buf.len() {
                break;
            }
            let start = pos;
            while pos < buf.len() && buf[pos] != 0 {
                pos += 1;
            }
            if let Ok(s) = std::str::from_utf8(&buf[start..pos])
                && !s.is_empty()
            {
                args.push(s.to_string());
            }
            pos += 1;
        }
        if args.is_empty() {
            None
        } else {
            Some(args.join(" "))
        }
    }
}

pub fn enrich_fd(conns: &mut [Connection]) {
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::proc_pid;
    // Per-process rlimit for arbitrary PIDs requires root on macOS; use the
    // system default (this process's limit) as the best available approximation.
    let limit = unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            rl.rlim_cur as usize
        } else {
            usize::MAX
        }
    };
    let mut cache: HashMap<u32, (usize, usize)> = HashMap::new();
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        let usage = cache.entry(pid).or_insert_with(|| {
            // pbi_nfiles is the kernel-reported open file count - more accurate
            // than listing FDs and avoids permission errors on foreign processes.
            let open = proc_pid::pidinfo::<BSDInfo>(pid as i32, 0)
                .map(|info| info.pbi_nfiles as usize)
                .unwrap_or(0);
            (open, limit)
        });
        c.fd_usage = Some(*usage);
    }
}

pub fn enrich_process_tree(conns: &mut [Connection]) {
    for c in conns.iter_mut() {
        let Some(pid) = c.pid else { continue };
        let chain = parent_chain(pid);
        if !chain.is_empty() {
            c.parent_chain = Some(chain);
        }
    }
}

fn parent_chain(pid: u32) -> String {
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::proc_pid;
    let mut parts = Vec::new();
    let mut current = pid;
    for _ in 0..5 {
        let Ok(info) = proc_pid::pidinfo::<BSDInfo>(current as i32, 0) else {
            break;
        };
        let ppid = info.pbi_ppid;
        if ppid <= 1 {
            break;
        }
        let name = proc_pid::name(ppid as i32).unwrap_or_else(|_| "?".to_string());
        parts.push(name);
        current = ppid;
        if parts.len() >= 4 {
            break;
        }
    }
    parts.join(" <- ")
}
