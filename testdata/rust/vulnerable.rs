// Rust testdata: intentionally vulnerable patterns for scanner testing.
use std::collections::HashMap;

// CWE-676: Use of potentially dangerous function (unsafe block)
fn read_raw_pointer() -> i32 {
    let x: i32 = 42;
    let raw = &x as *const i32;
    unsafe {
        *raw // unsafe dereference
    }
}

// CWE-190: Integer overflow — no checked arithmetic
fn unchecked_add(a: u8, b: u8) -> u8 {
    a + b // will panic in debug, wrap in release
}

// CWE-798: Hardcoded credential
const DB_PASSWORD: &str = "supersecret123";

// CWE-89: Command injection via format string passed to shell
use std::process::Command;

fn run_cmd(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", user_input)) // user_input not sanitized
        .output()
        .unwrap();
}

fn main() {
    println!("value: {}", read_raw_pointer());
    println!("sum: {}", unchecked_add(200, 100));
    println!("pass: {}", DB_PASSWORD);
    run_cmd("hello; rm -rf /");
}
