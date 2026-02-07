use clap::Parser;
use std::{
    io::{self, Read, Write},
    time::Duration,
};

#[derive(Parser)]
struct Args {
    serial_port: String,
    #[arg(default_value_t = 9_600)]
    baud_rate: u32,
}

fn main() {
    if let Err(err) = run(Args::parse()) {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut port = serialport::new(&args.serial_port, args.baud_rate)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    let mut stdout = io::stdout();
    let mut buffer = [0u8; 256];

    loop {
        match port.read(&mut buffer) {
            Ok(0) => {}
            Ok(count) => {
                for (index, byte) in buffer[..count].iter().enumerate() {
                    if index > 0 {
                        write!(stdout, " ")?;
                    }
                    write!(stdout, "{byte:02X}")?;
                }
                writeln!(stdout)?;
                stdout.flush()?;
            }
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {}
            Err(err) => return Err(Box::new(err)),
        }
    }
}
