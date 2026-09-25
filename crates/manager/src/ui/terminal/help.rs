pub(super) fn help_text() -> &'static str {
    r"NAVIGATE
↑ / ↓  Move between visible items
/  Search names, identifiers, and explanations
P  Show all attributes of the selected value
F  Filter by any identity or presentation attribute
T  Choose which attributes form the tree and reorder them
S  Open named view profiles; Enter loads, n saves new, s overwrites, d deletes
1 Required (external values only) · 2 All · 3 Keys · 4 Passwords · 5 Public info
6 Everyone · 7 Human-facing
?  Show or close this help

VIEW PROFILES
Saved in nix-secrets-profiles.toml in the repository. Profiles contain only view
settings: tree order, facet filters, type and audience. Search is never saved.
Opening the profile list keeps unsaved changes until you explicitly load one.
Other connected clients receive profile change notifications.

FACET FILTERS
Choose an attribute, then All, Whitelist, Blacklist, or a value.
Switching Whitelist and Blacklist inverts checked values to preserve the visible set.
From All, click a value for four choices: only this, only others,
whitelist this off, or blacklist all other values off.
Tree attributes remain filterable.

EDIT
Enter  Edit selected value; Enter again saves
Paste  Set from clipboard; replacement asks first
g  Generate password or passphrase for one field
G  Generate all missing passwords; keeps existing values
r  Reveal selected value
c  Copy the selected value
p  Copy the public half of a stored OpenSSH private key
d  Delete selected value after confirmation

DEPLOYMENT
A target deployer requests one server's values.
y  Approve the verified target and displayed changes
n / Esc  Reject the request

NOTICES
A success notice closes on the next key or click, which then acts as usual:
↓ moves the selection and S opens profiles. Esc and paste only close it.
Above a confirmation or entry dialog the key only closes the notice.
An error stays until Enter or its OK button; other input is ignored.

Esc  Leave a view, or quit from the tree"
}
