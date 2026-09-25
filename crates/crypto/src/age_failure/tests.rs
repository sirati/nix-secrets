use super::*;

#[test]
fn status_is_readable_and_report_line_is_dropped() {
    use std::os::unix::process::ExitStatusExt;
    let failure = AgeFailure::new(
        ExitStatus::from_raw(1 << 8),
        b"age: error: no identity matched any of the recipients\n\
          age: report unexpected or unhelpful errors at https://filippo.io/age/report\n",
    );
    assert_eq!(failure.status, "exit code 1");
    assert_eq!(
        failure.stderr,
        "age: error: no identity matched any of the recipients"
    );
    assert!(failure.hint.as_deref().unwrap().contains("recipient"));
    assert_eq!(describe_status(ExitStatus::from_raw(9)), "signal 9");
}

#[test]
fn key_material_and_control_characters_are_never_shown() {
    let cleaned = clean(
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n\
          got AGE-SECRET-KEY-1QQQ and AGE-PLUGIN-1P-1XYZ\x1b[31m\n",
    );
    assert!(!cleaned.contains("AGE-SECRET-KEY-1QQQ"));
    assert!(!cleaned.contains("AGE-PLUGIN-1P-1XYZ"));
    assert!(!cleaned.contains("BEGIN OPENSSH"));
    assert!(!cleaned.contains('\x1b'));
    assert!(clean(&[b'x'; 5000]).chars().count() <= SHOWN_CHARACTERS + 1);
}

#[test]
fn op_log_prefix_is_removed() {
    assert_eq!(
        strip_log_prefix(b"[ERROR] 2026/09/25 14:18:04 connecting to desktop app: read"),
        b"connecting to desktop app: read"
    );
}
