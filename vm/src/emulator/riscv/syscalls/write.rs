use crate::{compiler::riscv::register::Register, emulator::riscv::event_types::RvValue};

use super::{super::emulator::RiscvEmulator, Syscall, SyscallCode, SyscallContext};

pub(crate) struct WriteSyscall;

impl WriteSyscall {
    #[inline(always)]
    fn decode_len_usize(value: RvValue) -> usize {
        usize::try_from(value).expect("write syscall byte count does not fit usize")
    }
}

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
    /// - Put a hint into the input stream, as its next element.
    ///
    /// If the fd matches a hook in the hook registry, invoke the hook.
    ///
    /// Else, log a warning.
    #[allow(clippy::pedantic)]
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let a2 = Register::X12;
        let fd = u32::try_from(arg1).unwrap_or_else(|_| panic!("write fd overflow: {}", arg1));
        let write_buf = arg2;
        let nbytes = Self::decode_len_usize(ctx.rt.register(a2));
        // An empty write reads nothing, so its pointer may dangle, as an empty Rust slice's does.
        if nbytes > 0 && !ctx.allowed(write_buf, nbytes as u64, false) {
            return None;
        }
        let rt = &mut ctx.rt;
        // Read nbytes from memory starting at write_buf.
        let bytes = (0..nbytes)
            .map(|i| {
                let addr = write_buf
                    .checked_add(i as u64)
                    .expect("write syscall address overflow");
                rt.byte(addr)
            })
            .collect::<Vec<u8>>();
        let slice = bytes.as_slice();
        if fd == 1 || fd == 2 {
            let s = core::str::from_utf8(slice).unwrap();
            process_output(fd, ctx.rt, s);
        } else if fd == 3 {
            rt.state.public_values_stream.extend_from_slice(slice);
        } else if fd == 4 {
            // A hint is read next, ahead of any input the guest has not read yet; hints written
            // before one read come out newest first.
            let ptr = rt.state.input_stream_ptr;
            rt.state.input_stream.insert(ptr, slice.to_vec());
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
