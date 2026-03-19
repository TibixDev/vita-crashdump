use std::env;
use vita_crashdump::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <corefile.psp2dmp> <app.elf> [-s <stack_words>]", args[0]);
        std::process::exit(1);
    }

    let result = run_analysis(&args[1], &args[2]).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    // Print all crashed threads (or first thread if none crashed)
    let crashed: Vec<usize> = result.threads.iter()
        .enumerate()
        .filter(|(_, t)| t.crashed)
        .map(|(i, _)| i)
        .collect();

    let to_print = if crashed.is_empty() { vec![0] } else { crashed };

    for idx in to_print {
        print!("{}", result.format_thread_text(idx));
    }
}
