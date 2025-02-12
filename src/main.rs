use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <command> <args>", args[0]);
        return;
    }
    let mut command = std::process::Command::new(&args[1]);
    command.args(&args[2..]);
    let child = command.spawn().expect("failed to execute process");
    println!("PID: {}", child.id());
    let output = child
        .wait_with_output()
        .expect("failed to wait on child process");
    println!("status: {}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
}
