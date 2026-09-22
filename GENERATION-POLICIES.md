# Secret generation policies

A leaf may declare an optional `generation` policy. The policy authorizes the
frontend to generate a value for that exact schema leaf. It is public metadata;
the generated value still follows the normal encryption and approval path.
Policies work for ordinary stored leaves and for generated-task input leaves.

```nix
generation = {
  type = "random-password";
  length = 32; # 16 through 256
  alphabet = "ascii-safe"; # or "alphanumeric"
};
```

```nix
generation = {
  type = "random-passphrase";
  words = 8; # 6 through 24
  separator = "hyphen"; # "hyphen", "underscore", or "space"
  wordList = "eff-large";
};
```

```nix
generation = {
  type = "random-bytes";
  bytes = 32; # 16 through 4096, before encoding
  encoding = "base64url-unpadded"; # or "base64" or "hex"
};
```

Policy objects reject missing fields, extra fields, unknown enum values, and
values outside these bounds in both Nix normalization and Rust schema loading.
`alphanumeric` contains `A-Z`, `a-z`, and `0-9`. `ascii-safe` additionally
contains `!#$%&()*+,-./:;<=>?@[]^_{|}~`; it excludes whitespace, quotes,
backslash, and backtick. A byte policy's `bytes` count is the decoded length.
`eff-large` names the EFF long word list containing 7,776 entries.

`nix-secrets.lib.generators.backup` is an explicit convenience policy for 32
random bytes encoded as unpadded base64url. Assign it to a backup leaf:

```nix
services.nixSecrets.services.postgresql.secrets.repository-password = {
  destination = {
    path = "/persistent/secrets/postgresql/backup/repository-password";
    category = "backup";
    owner = "postgres-backup";
    group = "postgres-backup";
    mode = "0400";
  };
  generation = nix-secrets.lib.generators.backup;
};
```

The helper is never applied based on a destination category or service name.
Existing backup leaves retain their behavior until they declare `generation`.

Generation uses the operating-system CSPRNG. Index selection uses rejection
sampling, so alphabet characters and passphrase words are selected without
modulo bias. The TUI keeps the value in a zeroizing buffer, masks it until an
explicit reveal, and passes it directly to age encryption. Explicit copy sends
the value to the fixed `wl-copy` program through a pipe; it never places the
value in arguments, environment variables, logs, or temporary files. Desktop
clipboard confidentiality remains outside this program's trust boundary.
