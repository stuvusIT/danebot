# DaneBot

DaneBot uses dynamic DNS (RFC 2136) to automatically renew TLSA records for renewed TLS
certificates.
Certificate renewal itself is out of scope for DaneBot.

We suggest running DaneBot as a cron job once a day.
DaneBot simply parses a given certificate file (which might or might not have been
renewed since DaneBot's last run) and then performs the following steps:

1. Add TLSA record(s) for the certificate.
2. Wait for DNS propagation time + 2 * record TTL.
3. Run a user-specified hook. This hook should typically install the new certificate on
   the server, e.g., by copying the certificate and key to the server's configuration
   and reloading the server.
4. Remove old TLSA records.

Typically, you have a certificate file that gets renewed from time to time, e.g., by an
automatic certificate management tool.
Do NOT directly use that certificate file in your server configuration.
Instead, use a copy in your server configuration and let your hook (step 3) update this
copy.
This ensures that the server only uses the new certificate after corresponding TLSA
record(s) have been added and have propagated.

## Certificate and Key are Passed to the Hook

DaneBot requires a single PEM-encoded file containing both the certificate and
corresponding key (unencrypted).
(Having both in a single file eliminates race conditions with automated certificate
renewal tools running concurrently with DaneBot.)
With [Lego](https://github.com/go-acme/lego) such a file can be generated using the
`--pem` flag.

The hook (DaneBot's `--hook`) is run with the `DANEBOT_CERT` and `DANEBOT_KEY`
environment variables containing the new certificate and key (unencrypted) in
PEM-encoded format.

## Probe

When passing the `--probe` flag, DaneBot performs probes whether the server uses the new
certificate.
For that, DaneBot connects to the first domain given via -d/--domain using the first TCP
port given via --tcp and using SMTP with STARTTLS, in order to obtain the server's live
certificate.
One probe is done in the beginning and, if the server already uses the new certificate,
steps 2–3 are skipped, i.e., only the TLSA records are reconciled.
Another probe is done after running the hook (step 3) to verify that the hook
successfully installed the new certificate – an error is returned if that's not the
case.

Currently, DaneBot only supports SMTP-STARTTLS probes.
Thus, if you want to use DaneBot for something other than a mailserver, you need to omit
the `--probe` flag.

## Idempotency and Crash Safety

DaneBot is idempotent and can safely be rerun even if the certificate has not changed
since the last run.
We suggest using the `--probe` flag in order to skip the hook (and server reload) during
subsequent runs.

DaneBot can safely be interrupted and rerun at any time.

## Command Line Options

See `src/danebot.py --help`.

## Dependencies

`python3` with additional modules listed in `./requirements.txt`.

## Example Usage

The following example command reads a certificate from
[Lego](https://github.com/go-acme/lego) and updates the corresponding TLSA record
`_25._tcp.mx.example.com` on the authoritative nameserver `53.53.53.53`.
Of course, you need to replace `insert-name-here` and `insert-secret-here` by the name
and secret of a TSIG key with sufficient permissions.

```shell
export DANEBOT_RFC2136_TSIG_KEY=insert-name-here
export DANEBOT_RFC2136_TSIG_SECRET=insert-secret-here
src/danebot.py \
    --cert-file /etc/lego/.lego/certificates/mx.example.com.pem \
    --hook /etc/danebot/danebot-hook.sh \
    --rfc2136-nameserver 53.53.53.53 \
    -d mx.example.com \
    --tcp 25 \
    --ttl 3600 \
    --probe
```

You need to implement the hook `/etc/danebot/danebot-hook.sh` yourself.
The hook needs to be executable.
It might look like the following example, which installs the certificate on a postfix
server.

```bash
#!/usr/bin/env bash
# This is /etc/danebot/danebot-hook.sh
set -e
echo Installing certificate ...
install -m 600 <(echo "$DANEBOT_KEY" && echo "$DANEBOT_CERT") /etc/postfix/fullchain.pem
echo Reloading postfix ...
systemctl reload postfix
```

In above example, the postfix server needs to be configured with
`smtpd_tls_chain_files = /etc/postfix/fullchain.pem`.
This postfix configuration parameter can take a single PEM-encoded file containing the
key followed by the certificate.
