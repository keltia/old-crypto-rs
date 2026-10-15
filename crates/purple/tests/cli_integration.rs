//! End-to-end checks of the compiled purplectl executable.
use std::io::Write;
use std::process::{Command, Output, Stdio};

const TEXT: &str = "THEPURPLEMACHINEISNOWONLINE";
const CIPHER: &str = "OGIVTSIAAHMWMHTVIBYYJUOJFUE";

fn purplectl(args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_purplectl"))
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn purplectl");
    if let Some(input) = stdin {
        child.stdin.take().expect("stdin pipe").write_all(input.as_bytes())
            .expect("write CLI input");
    }
    child.wait_with_output().expect("wait for purplectl")
}

#[test]
fn encrypt_and_decrypt_published_vector() {
    for (action, input, expected) in [
        ("encrypt", TEXT, CIPHER),
        ("decrypt", CIPHER, TEXT),
    ] {
        let output = purplectl(&[action, input], None);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.stdout, format!("{expected}\n").as_bytes());
    }
}

#[test]
fn stdin_trailing_newline_and_explicit_yaml_configuration() {
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/config/reference.yaml");
    let output = purplectl(&["--config", config, "encrypt"], Some(&format!("{TEXT}\n")));
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, format!("{CIPHER}\n").as_bytes());
}

#[test]
fn rejects_invalid_input_and_missing_key_sheet() {
    for args in [
        vec!["encrypt", "HELLO WORLD"],
        vec!["encrypt", "hello"],
        vec!["--config", "no-such-purple-key-sheet.yaml", "encrypt", "HELLO"],
    ] {
        let output = purplectl(&args, None);
        assert!(!output.status.success(), "unexpected success: {args:?}");
        assert!(!output.stderr.is_empty(), "expected a useful diagnostic: {args:?}");
    }
}

#[test]
fn clap_help_is_available() {
    let output = purplectl(&["--help"], None);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("encrypt"));
    assert!(help.contains("decrypt"));
    assert!(help.contains("--config"));
}
