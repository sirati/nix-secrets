pub(super) fn help_text() -> &'static str {
    r"NAVIGATE
↑ / ↓  Move between visible items
Space  Collapse or expand the selected group (▾ expanded, ▸ collapsed)
-  Collapse all groups · +  Expand all groups
   Collapsed groups are kept for this session across refreshes, filters and
   tree reorders; profiles do not store them. While searching, every group
   holding a match is expanded, and folds made then last until the search
   changes; clearing the search restores the earlier folds
/  Search names, identifiers, and explanations
   While searching, the status line counts matches and those hidden by filters
P  Show all attributes of the selected value
F  Filter by any identity or presentation attribute
T  Choose which attributes form the tree and reorder them
S  Open named view profiles; Enter loads, n saves new, s overwrites, d deletes
O  Settings for this session (reset on restart; never saved to the repository)
C  Git Commit: commit nix-secrets.toml and nix-secrets-profiles.toml only
D  Deploy a host: pick it (the selected row's host is preselected) and every
   deployable value of it is requested; approve it like any deployment request.
   When the only missing values are derived from another host's unset value,
   p in the dialog deploys everything else and lists those as skipped; the
   host keeps waiting for them until their source host is deployed
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
Click  Select a row; a click on a group also collapses or expands it, and a
       click on an unset input value also opens its entry
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
d  Delete selected value after confirmation; a value never committed to git
   gets the same loss warning as replacing it
Replacing a set value asks after you enter the new one and press Enter.
Ctrl+R  In the entry field or that question: reveal the current stored value;
        closing the reveal returns to the dialog with your typed value
A value that was never committed to git gets a loss warning; only
Ctrl+Shift+Y or its Yes button overwrites it; n, Enter, Space and Esc keep it.
Terminals that cannot report Shift with Ctrl need the Yes button

GIT COMMIT (C)
Type the message; Enter adds a line. Tab or a click toggles Amend (fills in
the last message when empty), Ctrl+O or a click toggles Signoff.
Ctrl+E opens $VISUAL/$EDITOR here; Ctrl+S commits; Esc keeps the draft.
Only the two nix-secrets files are committed; other staged changes block it.
Signing uses the ssh-agent of this machine, relayed for that commit only.

DEPLOYMENT
A target deployer requests one server's values.
Unset passwords and values with a declared valueGenerator are generated on
the target; the request lists them, and a notice names them afterwards.
Other unset values block the request and are listed together.
Values derived from another secret are deployed from its current value.
y  Approve the verified target and displayed changes
n / Esc  Reject the request

SECRET REQUESTS
A program on the backend host (nix-secrets with-secrets or pipe-secret)
asks for values. A modal opens with a table of the values and their
kinds, the recipient, the key source, the requesting command, its
directory and parent, and a countdown. The dialog underneath is kept.
The terminal bell rings, a desktop notification is sent where the
terminal supports one, and the window title shows the request; the bell
rings again 30 s before the request expires.
Ctrl+Shift+Y or Yes  Decrypt all of them with one 1Password authorization
                     and send them to that program
d or Details         Show full descriptions, fingerprints and commands
n / Enter / Esc      Deny; the program gets nothing
c or Keep waiting    Cancel the countdown; the program is told and waits
After 120 s the request is denied unless c cancelled that. A notice names
the requester and whether the values were sent.

PROCEDURES
Prompts of one operation started with `nix-secrets procedure` (for
example SSH authentication, signing and deployment of an update) share
one dialog titled with the procedure and its step, such as
Update ns1 · step 2/4: sign closure for ns1. Any other request or
deployment is a procedure of its own. Only the first step of a procedure
counts down; later steps wait until answered.
m      Minimise the open secret request or deployment dialog
M      Restore the next procedure that waits for you, flashing ones first
Click  A task bar entry restores it
The task bar above the actions lists every procedure with its step and
whether it waits for you. A procedure never takes the screen from an open
dialog: one that starts meanwhile stays minimised and its entry flashes,
with a bell and a desktop notification. With nothing open it opens
directly. Several procedures can wait at once; the TUI handles one
deployment dialog at a time, and another procedure's deployment opens
once that one is answered.

CONNECTION
If the connection to the backend breaks (backend restart, SSH hiccup), the
status line says so and the TUI reconnects on its own, starting the backend
or its tunnel again when needed. Requests on screen disappear without an
answer and come back from the start once reconnected; an open deployment
dialog is discarded and offered again from its first step.

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
