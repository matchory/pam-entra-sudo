# pam-entra-sudo

A PAM module that lets sudo authenticate with a fresh Microsoft Entra ID
passkey sign-in, using the OAuth 2.0 device authorization grant
([RFC 8628](https://tools.ietf.org/html/rfc8628)).

It is the fallback for when no hardware key can be forwarded over SSH. sudo
prints a URL and a code, and the user signs in on any device, typically a
phone with a passkey. An agent running in a session nobody is watching can pass
the code on to the user.

Forked from [ICS-MU/pam_oauth2_device](https://github.com/ICS-MU/pam_oauth2_device)
(Apache-2.0). It has been reduced to the Entra case and rewritten; NOTICE
summarises the changes and the git history records each one.

## What it checks

1. It requests a device code with `prompt=login&max_age=0`, so Entra
   demands a new interactive sign-in instead of reusing a browser session.
2. sudo shows `sudo on <host>: sign in at <url> with code <code>` and the
   module polls the token endpoint until the user signs in, up to 5 minutes.
3. It checks the ID token:
   - `iss` and `tid` match the tenant, and `aud` is the client ID;
   - `exp` has not passed (60 s clock skew);
   - `auth_time` is present and at most `max_auth_age` seconds old. Entra
     only sends it when `max_age` is requested, so a reused session fails;
   - `amr` contains every method in `required_amr`. `fido` means a passkey
     or security key; a password plus Authenticator push gives `pwd`, `mfa`.
4. The token's `oid` must map to the local user in `users`.

## Process isolation

The module never talks to the network itself. sudo runs it as root with the
invoking user's environment, and classic sudo even replaces `getenv()` with
its own copy of that environment, so any library called in-process (libcurl
reads `SSLKEYLOGFILE` and `*_proxy`) would act on the user's variables as
root. Instead, each request goes to `/usr/libexec/pam-entra-sudo/fetch`,
started with `execve` and an empty environment, as the user `nobody` with
supplementary groups dropped and all of sudo's file descriptors closed. The
request goes in through a pipe and the response comes back through one,
capped at 64 KiB and 35 seconds. The module itself links only libpam.

`test/sudo_integration.sh` runs real sudo (classic with `-E`, and sudo-rs)
with a hostile environment and checks that no file is created and no proxy
is used; CI runs it on every release.

Every failure denies. The signature is not checked: the token comes straight
from Entra's token endpoint over TLS, which OIDC Core 3.1.3.7 accepts.

## Entra app

A single-tenant app registration with public client flows enabled, no API
permissions beyond `openid profile`, and `amr` added as an optional ID-token
claim.

## Configuration

`/etc/pam_entra_sudo.json`, readable by root only:

```json
{
  "tenant_id": "<directory (tenant) ID>",
  "client_id": "<application (client) ID>",
  "max_auth_age": 120,
  "required_amr": ["fido"],
  "users": {
    "<user object ID>": ["alice"]
  }
}
```

Every field is required. A missing or invalid field denies sudo.

`/etc/pam.d/sudo`, after the hardware-key line and before the deny:

```
auth  sufficient  pam_ssh_agent_auth.so file=/etc/ssh/authorized_keys_sudo/%u
auth  [success=done abort=die default=ignore]  pam_entra_sudo.so /etc/pam_entra_sudo.json
auth  requisite   pam_deny.so
```

`[success=done abort=die default=ignore]` is `sufficient` plus `abort=die`:
when the user presses Ctrl-C while the module waits, it returns `PAM_ABORT`
and the stack ends there. With plain `sufficient`, sudo would treat that as
a failed attempt and start another one with a new code.

The module logs to the `authpriv` facility as `pam_entra_sudo`.

## Building and testing

```bash
apt install build-essential libpam0g-dev libcurl4-openssl-dev nlohmann-json3-dev libgtest-dev python3
make
sudo make install            # module into the multiarch PAM directory,
                             # helper into /usr/libexec/pam-entra-sudo/
cd test && (./mock_server.py &) && make
```

The tests build the module against `test/mock_server.py` instead of Entra.
CI runs them on Ubuntu 20.04, 22.04, 24.04 and 26.04.

## Releases

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`: it tests and
builds `pam-entra-sudo_X.Y.Z.ubuntuNN.NN_amd64.deb` (package version
`X.Y.Z~ubuntuNN.NN`) for each supported Ubuntu release and publishes them
with `SHA256SUMS` as the GitHub release. Install
them by pinned checksum.
