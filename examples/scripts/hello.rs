use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <target> <port>", args[0]);
        std::process::exit(1);
    }
    println!("Hello from Rust: {}:{}", args[1], args[2]);
}
