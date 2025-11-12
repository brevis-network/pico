use crate::compiler::riscv::register::Register;

use super::{super::emulator::RiscvEmulator, Syscall, SyscallCode, SyscallContext};

pub(crate) struct WriteSyscall;

impl Syscall for WriteSyscall {
    /// Handle writes to file descriptors during emulation.
    ///
    /// If stdout (fd = 1):
    /// - If the stream is a cycle tracker, either log the cycle tracker or accumulate it in the
    ///   report.
    /// - Else, print the stream to stdout.
    ///
    /// If stderr (fd = 2):
    /// - Print the stream to stderr.
    ///
    /// If fd = 3:
    /// - Update the public value stream.
    ///
    /// If fd = 4:
    /// - Update the input stream.
    ///
    /// If the fd matches a hook in the hook registry, invoke the hook.
    ///
    /// Else, log a warning.
    #[allow(clippy::pedantic)]
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let a2 = Register::X12;
        let rt = &mut ctx.rt;
        let fd = arg1;
        let write_buf = arg2;
        let nbytes = rt.register(a2);
        // Read nbytes from memory starting at write_buf.
        let bytes = (0..nbytes)
            .map(|i| rt.byte(write_buf + i))
            .collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        if fd == 1 || fd == 2 {
            let s = core::str::from_utf8(slice).unwrap();
            process_output(fd, ctx.rt, s);
        } else if fd == 3 {
            rt.state.public_values_stream.extend_from_slice(slice);
        } else if fd == 4 {
            rt.state.input_stream.push(slice.to_vec());
        } else if let Some(hook) = rt.hook_map.get(&fd) {
            let result = hook(rt, slice);
            let ptr = rt.state.input_stream_ptr;
            rt.state.input_stream.splice(ptr..ptr, result);
        } else {
            tracing::warn!("tried to write to unknown file descriptor {fd}");
        }
        None
    }
}

fn process_output(fd: u32, rt: &mut RiscvEmulator, s: &str) {
    // use core::mem::take to avoid borrowing
    let (prefix, mut buffer) = match fd {
        1 => ("stdout", core::mem::take(&mut rt.stdout)),
        2 => ("stderr", core::mem::take(&mut rt.stderr)),
        _ => unreachable!(),
    };

    buffer.push_str(s);
    let mut remaining = buffer.as_str();
    while let Some((l, r)) = remaining.split_once('\n') {
        log::info!("{}> {}", prefix, l);
        if rt.opts.cycle_tracker {
            process_cycle_tracker(l, rt);
        }
        remaining = r;
    }
    let remaining = remaining.to_owned();

    // put the remainder back
    match fd {
        1 => core::mem::replace(&mut rt.stdout, remaining),
        2 => core::mem::replace(&mut rt.stderr, remaining),
        _ => unreachable!(),
    };
}

fn process_cycle_tracker(line: &str, rt: &mut RiscvEmulator) {
    if let Some(start) = line.strip_prefix("cycle-tracker-start: ") {
        let clk = rt.state.global_clk;
        log::info!("cycle-tracker> started tracker for '{start}' at {clk}");
        rt.cycle_tracker_requests.insert(start.to_owned(), clk);
    } else if let Some(end) = line.strip_prefix("cycle-tracker-end: ") {
        let end = end.to_owned();
        let clk = rt.state.global_clk;
        let start = *rt
            .cycle_tracker_requests
            .entry_ref(&end)
            .or_insert(rt.state.global_clk);
        log::info!(
            "cycle-tracker> ended tracker for '{end}' at {clk} with value {}",
            clk - start
        );
        rt.cycle_tracker.entry(end).or_default().push(clk - start);
    }
}
