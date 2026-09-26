//! Committing from the TUI: only the managed files, signed by the
//! frontend's ssh-agent through the backend's temporary relay socket.

use nix_secrets_core::git::CommitOptions;
use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_manager::client::BackendClient;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "{arguments:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

struct Agent {
    child: Child,
    socket: PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A private ssh-agent holding `key`.
fn agent(directory: &Path, key: &Path) -> Agent {
    let socket = directory.join("agent.sock");
    let child = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&socket)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let added = Command::new("ssh-add")
        .arg(key)
        .env("SSH_AUTH_SOCK", &socket)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(added.success());
    Agent { child, socket }
}

#[test]
fn a_commit_is_signed_through_the_relayed_agent() {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("repo");
    std::fs::create_dir(&repository).unwrap();
    let key = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "signer", "-f"])
        .arg(&key)
        .status()
        .unwrap()
        .success());
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let allowed = temp.path().join("allowed_signers");
    std::fs::write(&allowed, format!("test@example.invalid {public}")).unwrap();

    git(&repository, &["init", "-q", "-b", "main"]);
    for (name, value) in [
        ("user.name", "test"),
        ("user.email", "test@example.invalid"),
        ("gpg.format", "ssh"),
        ("commit.gpgsign", "true"),
        ("user.signingkey", public.trim()),
        // A desktop signer that cannot run here; the relay replaces it.
        ("gpg.ssh.program", "/nonexistent/op-ssh-sign"),
        ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
    ] {
        git(&repository, &["config", name, value]);
    }
    std::fs::write(repository.join("flake.nix"), "{ }\n").unwrap();
    std::fs::write(repository.join("nix-secrets.toml"), "[secrets]\n").unwrap();
    git(&repository, &["add", "."]);
    git(
        &repository,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "initial",
        ],
    );
    std::fs::write(repository.join("nix-secrets.toml"), "[secrets]\n# new\n").unwrap();
    std::fs::write(repository.join("flake.nix"), "{ unrelated = 1; }\n").unwrap();

    let socket = temp.path().join("backend.sock");
    let schema = Schema::from_json("{}").unwrap();
    let backend = Backend::bind(
        &socket,
        schema,
        SecretStore::new(repository.join("nix-secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve());
    let agent = agent(temp.path(), &key);
    let runtime = temp.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    // The backend creates its relay socket under XDG_RUNTIME_DIR.
    std::env::set_var("XDG_RUNTIME_DIR", &runtime);

    let mut client = BackendClient::new(std::os::unix::net::UnixStream::connect(&socket).unwrap());
    let summary = client.commit_summary().unwrap();
    assert!(summary.signs);
    assert!(summary.diff_stat.contains("nix-secrets.toml"));
    let result = client
        .commit(
            CommitOptions {
                message: "Store secrets".into(),
                amend: false,
                signoff: false,
            },
            Some(&agent.socket),
        )
        .unwrap()
        .unwrap();
    assert_eq!(result.hash, git(&repository, &["rev-parse", "HEAD"]).trim());
    assert_eq!(
        git(
            &repository,
            &[
                "-c",
                "gpg.ssh.program=ssh-keygen",
                "log",
                "-1",
                "--format=%G?"
            ]
        )
        .trim(),
        "G",
        "the commit carries a good signature by the agent's key"
    );
    assert_eq!(
        git(&repository, &["show", "--name-only", "--format=", "HEAD"]).trim(),
        "nix-secrets.toml"
    );
    assert!(git(&repository, &["status", "--porcelain"]).contains(" M flake.nix"));
    // The relay socket and its directory are gone.
    assert_eq!(std::fs::read_dir(&runtime).unwrap().count(), 0);

    // Without an agent the configured signer runs, fails, and git's error
    // comes back whole.
    std::fs::write(repository.join("nix-secrets.toml"), "[secrets]\n# newer\n").unwrap();
    let error = client
        .commit(
            CommitOptions {
                message: "Unsigned".into(),
                amend: false,
                signoff: false,
            },
            None,
        )
        .unwrap()
        .unwrap_err();
    assert!(
        error.contains("op-ssh-sign") || error.contains("sign"),
        "{error}"
    );
    assert_eq!(
        git(&repository, &["rev-list", "--count", "HEAD"]).trim(),
        "2"
    );
}
