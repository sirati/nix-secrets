pub(super) fn help_text() -> &'static str {
    r"NAVIGATE
↑ / ↓  Move between visible items
/  Search names, identifiers, and explanations
   While searching, the status line counts matches and those hidden by filters
P  Show all attributes of the selected value
F  Filter by any identity or presentation attribute
T  Choose which attributes form the tree and reorder them
S  Open named view profiles; Enter loads, n saves new, s overwrites, d deletes
O  Settings for this session (reset on restart; never saved to the repository)
1 Required (external values, and unset values needed before install) · 2 All · 3 Keys · 4 Passwords · 5 Public info
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
Click  Select a row; a click on an unset input value also opens its entry
Paste  Set from clipboard; replacement asks first
Tab    In the entry field: toggle 'Autosave unset on paste'. When on, pasting
       one line into an unset value saves it at once. Clicking the checkbox or its
       label toggles it
Ctrl+V Read the clipboard directly over X11 or Xwayland, without opening a
       window; works when the terminal's own paste fails
g  Generate password or passphrase; on an operator key, run its generator
G  Generate all missing passwords; keeps existing values
r  Reveal selected value
c  Copy the selected value
p  Copy the public half of an OpenSSH private key or an operator key
d  Delete selected value after confirmation
Replacing a set value asks after you enter the new one and press Enter.
Ctrl+R  In the entry field or that question: reveal the current stored value;
        closing the reveal returns to the dialog with your typed value
A value that was never committed to git gets a loss warning; only
Ctrl+Shift+Y or its Yes button overwrites it; n, Enter, Space and Esc keep it.
Terminals that cannot report Shift with Ctrl need the Yes button

DEPLOYMENT
A target deployer requests one server's values.
Unset passwords and values with a declared valueGenerator are generated on
the target; the request lists them, and a notice names them afterwards.
Other unset values block the request and are listed together.
Values derived from another secret are deployed from its current value.
y  Approve the verified target and displayed changes
n / Esc  Reject the request

WORKING
A strip at the top names a running decryption or save and counts seconds.
It may be waiting for a 1Password approval prompt. The rest of the screen
stays usable.

NOTICES
A success notice closes on the next key or click, which then acts as usual:
↓ moves the selection and S opens profiles. Esc and paste only close it.
Above a confirmation or entry dialog the key only closes the notice.
An error stays until Enter or its OK button; other input is ignored.

Esc  Leave a view, or quit from the tree"
}
