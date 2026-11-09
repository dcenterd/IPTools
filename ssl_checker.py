#!/usr/bin/env python3
# Written by Zareh
# Gifted to Seyed Mesbah Ahmadi
"""Check SSL certificate validity/expiry/revocation for many websites and report only CHANGES.

QUICK START (permanent setup on Linux, alerts to Telegram/Discord/Slack/Teams/any webhook)
  1. sites.txt - one site per line (re-read every run, so edits need no restart).
  2. Put the webhook in a private env file (NOT on the command line, `ps` would show it):
       mkdir -p ~/.config/ssl-checker
       echo 'SSL_WEBHOOKS=telegram://BOT_TOKEN@CHAT_ID' > ~/.config/ssl-checker/env
       chmod 600 ~/.config/ssl-checker/env
  3. Run it as a systemd user service - see "NOTES - running in the background", option 3.
  4. Test the webhook once:  SSL_WEBHOOKS=... python3 -c "import ssl_checker as m, os; \\
       m.send_webhook(os.environ['SSL_WEBHOOKS'], 'ssl-checker test')"
  You are notified only when something changes (see "NOTES - change detection"); an
  unchanged site produces no output and no alert.

Usage:
  ssl_checker.py example.com https://github.com:443
  ssl_checker.py -f sites.txt --warn-days 30
  ssl_checker.py -f sites.txt --webhook https://hooks.slack.com/services/XXX
  ssl_checker.py -f sites.txt --webhook telegram://123456:ABC-DEF@-1001234567890 --webhook https://discord.com/api/webhooks/...
  ssl_checker.py -f sites.txt --email you@example.com --smtp-host smtp.gmail.com \\
      --smtp-port 587 --smtp-user you@gmail.com --smtp-pass APP_PASSWORD

  ssl_checker.py -f sites.txt --check-revocation --webhook ...

Run repeatedly / in the background:
  ssl_checker.py -f sites.txt --every 6h --background       (every 6 hours, until killed)
  ssl_checker.py -f sites.txt --at 09:00 --for 30d --background   (daily at 09:00 for 30 days)

NOTE: --background only works on Linux/Unix (it uses fork). On Windows, run the script in a
foreground terminal or use Task Scheduler instead.

NOTES - change detection (state file)
-------------------------------------
Each run is compared with the previous one (saved in --state-file). Output and alerts happen
only when something CHANGED: status (OK -> REVOKED/EXPIRED/INVALID/..., or back to OK =
RECOVERED), or the certificate was replaced (new SHA-256 fingerprint, e.g. a renewal). A
problem present on the very first run is reported once; an unchanged problem is not repeated.
Day counters do not count as changes. If every alert channel fails, the change is kept
pending and re-sent next run. Use --verbose for the old print-everything behavior; delete the
state file to start fresh. The exit code still reflects the current state (1 = a problem exists).

NOTES - revocation checking (--check-revocation)
------------------------------------------------
Why: a certificate can be revoked by its CA before its expiry date (stolen key, mis-issued
cert). Python's ssl module only checks the chain, hostname and dates - NOT revocation - so
a revoked cert can look "OK" here while Chrome/Firefox block it. This flag closes that gap.

What is an OCSP responder? A server run by the CA (OCSP = Online Certificate Status
Protocol). A client sends it a certificate's serial number + issuer, and it returns a signed
answer: good, revoked (with time/reason) or unknown. The responder URL is stored in the
certificate's "Authority Information Access" field.
What is a CRL? A downloadable list of every revoked serial number from a CA. The URL is in
the certificate's "CRL Distribution Points" field. Larger and slower than OCSP, but it works
when a CA has no OCSP responder (e.g. Let's Encrypt has dropped OCSP in favour of CRLs).

How the script does it (needs the `openssl` CLI):
  1. Normal check first: connect, verify chain/hostname, read the expiry date.
  2. With --check-revocation, fetch the server's chain (`openssl s_client -showcerts`).
     The first cert is the site (leaf), the second is its issuer.
  3. OCSP: if the leaf lists a responder, ask it (`openssl ocsp`) about the leaf's serial.
       revoked -> status REVOKED     good -> OK     no answer -> try the CRL
  4. CRL fallback: download the CRL from the leaf's CRL address and look for the leaf's
     serial number in it. Listed -> REVOKED, not listed -> OK.
  5. If nothing could be checked (no OCSP/CRL address, responder down, no openssl), the
     site stays OK but the message says "(revocation not verified: ...)". A failed check is
     never reported as a clean result.
  Certificates that already fail verification (invalid, incomplete chain) skip this step.

Status meanings: REVOKED = the CA revoked it (alerts + exit code 1, like EXPIRED).
Limits: this only reflects what the CA publishes. Chrome's CRLSets and Firefox's CRLite
can flag a cert earlier, so a browser may still block a site that this script shows as OK.
It adds a few seconds per site, which is why it is opt-in.

NOTES - webhooks (--webhook, env SSL_WEBHOOKS)
----------------------------------------------
--webhook is repeatable and the service is detected from the URL.

Plain webhook URLs (the URL already identifies the channel, no chat ID needed):
  Discord, Slack/Mattermost incoming webhooks, Microsoft Teams, or any other URL (generic JSON).

Bot-token URLs (token + target ID in one URL, like Telegram; the ID is case-sensitive):
  telegram://BOT_TOKEN@CHAT_ID                   e.g. telegram://123456:ABC-DEF@-1001234567890
  slack-bot://xoxb-TOKEN@CHANNEL_ID              e.g. slack-bot://xoxb-1-2-abc@C0123ABCDEF
        (Slack app with chat:write, invited to the channel; Slack errors are detected)
  discord-bot://BOT_TOKEN@CHANNEL_ID             bot needs Send Messages in that channel
  matrix://ACCESS_TOKEN@HOMESERVER/ROOM_ID       e.g. matrix://syt_abc@matrix.org/!room:matrix.org
        (quote the URL in the shell: "!" is special)
  bale://BOT_TOKEN@CHAT_ID                       Bale messenger, same bot API as Telegram
  ntfy://TOPIC  or  ntfy://[TOKEN@]HOST/TOPIC    ntfy.sh (or your server); subscribe to the topic in the app
  pushover://APP_TOKEN@USER_KEY                  Pushover push notifications
  gotify://APP_TOKEN@HOST                        your own Gotify server (https)
Also plain webhook URLs: Google Chat (chat.googleapis.com), Rocket.Chat (.../hooks/...).
To support another messenger, add one (matcher, builder) entry to FORMATTERS. Failures are
logged without the URL, so bot tokens stay out of logs.

NOTES - running in the background on Linux
------------------------------------------
1) Built-in (quick, does NOT survive a reboot):
     ssl_checker.py -f sites.txt --check-revocation --every 6h --background
     ssl_checker.py -f sites.txt --check-revocation --at 09:00 --for 30d --background
   Output goes to ssl_checker.log (--log-file), PID to ssl_checker.pid (--pid-file).
   Watch: tail -f ssl_checker.log      Stop: kill $(cat ssl_checker.pid)
   The state file (ssl_checker.state.json) is created in the current directory.
   Tip: put the webhook in the environment instead of the command line, so the bot token
   is not visible in `ps`:  export SSL_WEBHOOKS="telegram://BOT_TOKEN@CHAT_ID"
2) cron (survives reboots) - `crontab -e`, use absolute paths. cron starts in your home
   directory, so ALWAYS pass an absolute --state-file or change detection loses its memory:
     0 */6 * * * SSL_WEBHOOKS="telegram://BOT_TOKEN@CHAT_ID" /usr/bin/python3 /path/ssl_checker.py -f /path/sites.txt --check-revocation --state-file /path/ssl_checker.state.json >> /path/cron.log 2>&1
3) systemd user service (survives reboots, restarts on crash) - recommended for permanent use.
   Create ~/.config/systemd/user/ssl-checker.service:
     [Unit]
     Description=SSL certificate change checker
     [Service]
     WorkingDirectory=/path/to/SSLChecker
     EnvironmentFile=%h/.config/ssl-checker/env
     ExecStart=/usr/bin/python3 ssl_checker.py -f sites.txt --check-revocation --every 6h
     Restart=on-failure
     RestartSec=300
     [Install]
     WantedBy=default.target
   Then (stop any --background instance first: kill $(cat ssl_checker.pid)):
         systemctl --user daemon-reload && systemctl --user enable --now ssl-checker
         loginctl enable-linger $USER          (keep running after logout)
         journalctl --user -u ssl-checker -f   (logs)
   Do not use --background under systemd; it already runs the process in the background.
   RestartSec=300 matters: the script exits when a site is unreachable (DNS_ERROR/ERROR), and
   without a delay systemd would restart it in a tight loop. Fix or remove the site to stop it.
   To force a test alert: stop the service, edit a site's "status" in the state file, start it.

Exit code: 0 = all OK, 1 = at least one WARNING/EXPIRED/INVALID/ERROR.
Suitable for cron:  0 */6 * * * /usr/bin/python3 /path/ssl_checker.py -f sites.txt --webhook URL

The --smtp-* flags default to the env vars SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS.
Optional sender address: SMTP_FROM (defaults to the SMTP user).
"""
import argparse
import hashlib
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import quote, urlparse


def parse_target(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "//" + raw
    u = urlparse(raw)
    return u.hostname, u.port or 443


def get_issuer(cert):
    """Flatten the cert's issuer RDNs into a dict, e.g. {'organizationName': 'Let's Encrypt', ...}."""
    return {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}


def format_issuer(issuer):
    if not issuer:
        return ""
    name = issuer.get("organizationName", "")
    cn = issuer.get("commonName", "")
    country = issuer.get("countryName", "")
    return ", ".join(x for x in (cn, name, country) if x)


def inspect_unverified(host, port, timeout):
    """Fetch a cert that failed verification and read its details (needs `pip install cryptography`).

    Returns {"issuer": str, "expires": datetime} or {} if cryptography is missing or the fetch fails.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
    except (OSError, ValueError):
        return {}

    def attr(oid):
        vals = cert.issuer.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""

    issuer = {"commonName": attr(NameOID.COMMON_NAME),
              "organizationName": attr(NameOID.ORGANIZATION_NAME),
              "countryName": attr(NameOID.COUNTRY_NAME)}
    expires = getattr(cert, "not_valid_after_utc", None)
    if expires is None:  # cryptography < 42
        expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return {"issuer": format_issuer(issuer), "expires": expires,
            "fingerprint": hashlib.sha256(der).hexdigest()}


def dump_cert(host, port, timeout, out_dir):
    """Save the server's leaf certificate as PEM (fetched without verification, so
    expired/self-signed/wrong-host certs can be dumped too). Returns the file path or ''."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{host.replace(':', '_')}_{port}.pem")
        pem = ssl.DER_cert_to_PEM_cert(der)
        with open(path, "w") as fh:
            fh.write(pem)
        decode_cert(pem, path[:-4] + ".txt")
        return path
    except OSError:
        return ""


def decode_cert(pem, txt_path):
    """Write the human-readable decode (same as `openssl x509 -text -noout`) next to the PEM."""
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem, text=True,
                             capture_output=True, timeout=10, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        out = f"could not decode certificate (is the openssl CLI installed?): {e}\n"
    with open(txt_path, "w") as fh:
        fh.write(out)


def _openssl(args, stdin=None, timeout=15, binary=False):
    """Run the openssl CLI; returns (returncode, stdout, stderr). Raises OSError/SubprocessError."""
    r = subprocess.run(["openssl"] + args, input=stdin, capture_output=True, timeout=timeout,
                       text=not binary)
    return r.returncode, r.stdout, r.stderr


def fetch_chain_pem(host, port, timeout):
    """Return the server-sent certificates as a list of PEM strings (leaf first)."""
    _, out, _ = _openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
                         stdin="", timeout=timeout + 5)
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)


def check_revocation(host, port, timeout):
    """Check revocation via OCSP, falling back to the CRL. Returns (state, detail) where state is
    'good', 'revoked' or 'unknown' (no responder, unreachable, or issuer not sent by the server)."""
    import tempfile
    try:
        chain = fetch_chain_pem(host, port, timeout)
        if not chain:
            return "unknown", "could not read the certificate chain"
        leaf = chain[0]
        with tempfile.TemporaryDirectory() as tmp:
            leaf_f = os.path.join(tmp, "leaf.pem")
            open(leaf_f, "w").write(leaf)
            text = _openssl(["x509", "-noout", "-text", "-serial"], stdin=leaf)[1]
            serial = re.search(r"^serial=([0-9A-Fa-f]+)", text, re.M).group(1).upper().lstrip("0")
            ocsp = re.search(r"OCSP - URI:(\S+)", text)
            crls = re.findall(r"URI:(http\S+\.crl\S*|http\S+)", text.split("CRL Distribution Points")[1]
                              .split("Authority Information Access")[0]) if "CRL Distribution Points" in text else []
            reasons = []

            # 1) OCSP (needs the issuer, which servers normally send as the 2nd cert)
            if ocsp and len(chain) > 1:
                iss_f = os.path.join(tmp, "issuer.pem")
                open(iss_f, "w").write(chain[1])
                url = ocsp.group(1)
                rc, out, err = _openssl(["ocsp", "-issuer", iss_f, "-cert", leaf_f, "-url", url,
                                         "-header", "Host", urlparse(url).hostname,
                                         "-timeout", str(timeout), "-noverify"], timeout=timeout + 5)
                m = re.search(r"leaf\.pem: (good|revoked|unknown)", out + err)
                if m and m.group(1) == "revoked":
                    when = re.search(r"Revocation Time: (.+)", out)
                    return "revoked", "OCSP: revoked" + (f" on {when.group(1)}" if when else "")
                if m and m.group(1) == "good":
                    return "good", "OCSP: good"
                reasons.append("OCSP gave no answer")
            elif ocsp:
                reasons.append("OCSP skipped (issuer cert not sent by server)")

            # 2) CRL fallback
            for url in crls[:2]:
                try:
                    with urllib.request.urlopen(url, timeout=timeout) as resp:
                        data = resp.read(50_000_000)
                    fmt = "PEM" if data.lstrip().startswith(b"-----BEGIN") else "DER"
                    rc, out, err = _openssl(["crl", "-inform", fmt, "-noout", "-text"], stdin=data,
                                            timeout=60, binary=True)
                    if rc != 0:
                        reasons.append("CRL unreadable")
                        continue
                    out = out.decode(errors="replace")
                    for m in re.finditer(r"Serial Number:\s*([0-9A-Fa-f]+)(.*?)(?=Serial Number:|\Z)", out, re.S):
                        if m.group(1).upper().lstrip("0") == serial:
                            when = re.search(r"Revocation Date: (.+)", m.group(2))
                            return "revoked", "CRL: revoked" + (f" on {when.group(1).strip()}" if when else "")
                    return "good", "CRL: not listed"
                except (OSError, ValueError) as e:
                    reasons.append(f"CRL fetch failed ({type(e).__name__})")
            if not ocsp and not crls:
                reasons.append("certificate has no OCSP/CRL address")
            return "unknown", "; ".join(reasons) or "no revocation info"
    except (OSError, subprocess.SubprocessError, AttributeError) as e:
        return "unknown", f"revocation check failed ({type(e).__name__}: {e}); is the openssl CLI installed?"


def check(target, timeout, warn_days, dump_dir=None, revocation=False):
    result = _check(target, timeout, warn_days)
    result["cert_file"] = ""
    if revocation and result["host"] and result["status"] in ("OK", "WARNING", "EXPIRED"):
        state, detail = check_revocation(result["host"], result["port"], timeout)
        result["revocation"] = detail
        if state == "revoked":
            result.update(status="REVOKED", message=detail)
        elif state == "unknown" and result["status"] == "OK":
            result["message"] += f" (revocation not verified: {detail})"
    if dump_dir and result["host"] and result["status"] not in ("DNS_ERROR", "ERROR"):
        result["cert_file"] = dump_cert(result["host"], result["port"], timeout, dump_dir)
    return result


def _check(target, timeout, warn_days):
    host, port = parse_target(target)
    result = {"target": target, "host": host, "port": port, "status": "OK",
              "days_left": None, "expires": None, "issuer": "", "message": "",
              "fingerprint": ""}
    if not host:
        result.update(status="ERROR", message="could not parse host")
        return result

    ctx = ssl.create_default_context()  # verifies chain + hostname
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result["fingerprint"] = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        result.update(expires=expires.strftime("%Y-%m-%d"), days_left=days,
                      issuer=format_issuer(get_issuer(cert)))
        if days < 0:
            result.update(status="EXPIRED", message=f"expired {-days} days ago")
        elif days <= warn_days:
            result.update(status="WARNING", message=f"expires in {days} days")
        else:
            result["message"] = f"valid, expires in {days} days"
    except ssl.SSLCertVerificationError as e:
        # 20 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: server omitted the intermediate cert
        status = {20: "INCOMPLETE_CHAIN", 10: "EXPIRED"}.get(e.verify_code, "INVALID")
        message = e.verify_message or str(e)
        if status == "EXPIRED":
            message = "certificate has expired"
        if status == "INCOMPLETE_CHAIN":
            message += " (server is not sending the intermediate certificate)"
        result.update(status=status, message=message)
        info = inspect_unverified(host, port, timeout)
        if info:
            result.update(issuer=info["issuer"], expires=info["expires"].strftime("%Y-%m-%d"),
                          days_left=(info["expires"] - datetime.now(timezone.utc)).days,
                          fingerprint=info["fingerprint"])
    except ssl.SSLError as e:
        result.update(status="INVALID", message=f"SSL error: {e}")
    except (socket.timeout, TimeoutError):
        result.update(status="ERROR", message="connection timed out")
    except socket.gaierror as e:
        result.update(status="DNS_ERROR", message=f"DNS lookup failed, domain does not resolve ({e.strerror})")
    except OSError as e:
        result.update(status="ERROR", message=f"connection failed: {e}")
    return result


def _telegram(url, text, api="https://api.telegram.org"):
    # telegram://BOT_TOKEN@CHAT_ID  ->  Bot API sendMessage
    u = urlparse(url)
    token = f"{u.username}:{u.password}" if u.password else u.username
    return (f"{api}/bot{token}/sendMessage", {"chat_id": u.hostname, "text": text[:4096]})


def _bale(url, text):
    # bale://BOT_TOKEN@CHAT_ID  ->  Bale's Bot API, same format as Telegram's
    return _telegram(url, text, api="https://tapi.bale.ai")


def _split_target(url):
    """'scheme://TOKEN@TARGET' -> (TOKEN, TARGET), keeping case (URL parsing would lowercase IDs)."""
    token, _, target = url.split("://", 1)[1].rpartition("@")
    if not token or not target:
        raise ValueError(f"expected {url.split('://')[0]}://TOKEN@TARGET")
    return token, target


def _slack_bot(url, text):
    # slack-bot://xoxb-TOKEN@CHANNEL_ID  ->  chat.postMessage (bot needs chat:write, invited to channel)
    token, channel = _split_target(url)

    def check(body):  # Slack answers HTTP 200 even on errors; the real result is in the JSON
        if not json.loads(body).get("ok"):
            raise RuntimeError(f"Slack error: {json.loads(body).get('error', 'unknown')}")
    return ("https://slack.com/api/chat.postMessage", {"channel": channel, "text": text},
            {"headers": {"Authorization": f"Bearer {token}"}, "check": check})


def _discord_bot(url, text):
    # discord-bot://BOT_TOKEN@CHANNEL_ID  ->  create message (bot needs Send Messages in that channel)
    token, channel = _split_target(url)
    return (f"https://discord.com/api/v10/channels/{channel}/messages", {"content": text[:2000]},
            {"headers": {"Authorization": f"Bot {token}", "User-Agent": "ssl-checker (script, 1.0)"}})


def _ntfy(url, text):
    # ntfy://TOPIC  |  ntfy://[ACCESS_TOKEN@]HOST/TOPIC  (default server ntfy.sh)  ->  JSON publish
    rest = url.split("://", 1)[1]
    token, _, rest = rest.rpartition("@")
    server, _, topic = rest.rpartition("/")
    if not topic:
        raise ValueError("expected ntfy://[TOKEN@][HOST/]TOPIC")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return (f"https://{server or 'ntfy.sh'}/", {"topic": topic, "title": "SSL checker", "message": text},
            {"headers": headers})


def _pushover(url, text):
    # pushover://APP_TOKEN@USER_OR_GROUP_KEY
    token, user = _split_target(url)
    return ("https://api.pushover.net/1/messages.json",
            {"token": token, "user": user, "title": "SSL checker", "message": text[:1024]})


def _gotify(url, text):
    # gotify://APP_TOKEN@HOST  (your own Gotify server, https)
    token, host = _split_target(url)
    return (f"https://{host}/message?token={quote(token, safe='')}",
            {"title": "SSL checker", "message": text, "priority": 5})


def _matrix(url, text):
    # matrix://ACCESS_TOKEN@homeserver.example/!ROOM_ID:homeserver.example  ->  send m.room.message
    token, target = _split_target(url)
    server, _, room = target.partition("/")
    if not room:
        raise ValueError("expected matrix://ACCESS_TOKEN@HOMESERVER/ROOM_ID")
    txn = f"sslchecker{time.time_ns()}"
    return (f"https://{server}/_matrix/client/v3/rooms/{quote(room, safe='')}/send/m.room.message/{txn}",
            {"msgtype": "m.text", "body": text},
            {"headers": {"Authorization": f"Bearer {token}"}, "method": "PUT"})


# To support a new messenger: add (matcher, builder). Builder returns (final_url, json_payload)
# and may add a third item: {"headers": {...}, "method": "PUT", "check": fn(response_body)}.
FORMATTERS = [
    (lambda u: u.startswith("telegram://"), _telegram),
    (lambda u: u.startswith("slack-bot://"), _slack_bot),
    (lambda u: u.startswith("discord-bot://"), _discord_bot),
    (lambda u: u.startswith("matrix://"), _matrix),
    (lambda u: u.startswith("bale://"), _bale),
    (lambda u: u.startswith("ntfy://"), _ntfy),
    (lambda u: u.startswith("pushover://"), _pushover),
    (lambda u: u.startswith("gotify://"), _gotify),
    (lambda u: "chat.googleapis.com" in u,  # Google Chat incoming webhook
     lambda u, t: (u, {"text": t})),
    (lambda u: "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u,
     lambda u, t: (u, {"content": t})),
    (lambda u: "hooks.slack.com" in u or "/hooks/" in u,  # Slack, Mattermost
     lambda u, t: (u, {"text": t})),
    (lambda u: "webhook.office.com" in u,  # Microsoft Teams
     lambda u, t: (u, {"text": t})),
]


def send_webhook(url, text):
    for match, build in FORMATTERS:
        if match(url):
            target, payload, *extra = build(url, text)
            break
    else:  # unknown service: generic JSON
        target, payload, extra = url, {"text": text, "content": text}, []
    opts = extra[0] if extra else {}
    req = urllib.request.Request(target, json.dumps(payload).encode(),
                                 {"Content-Type": "application/json", **opts.get("headers", {})},
                                 method=opts.get("method", "POST"))
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
    if "check" in opts:
        opts["check"](body)


def webhook_urls(args):
    """All webhook URLs from repeated --webhook flags plus the SSL_WEBHOOKS env var (comma-separated)."""
    urls = list(args.webhook or [])
    urls += [u.strip() for u in os.environ.get("SSL_WEBHOOKS", "").split(",") if u.strip()]
    return urls


def send_email(to, subject, text, host, port, user, password):
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, to
    msg["From"] = os.environ.get("SMTP_FROM", user or "ssl-checker@localhost")
    msg.set_content(text)
    with smtplib.SMTP(host, port, timeout=15) as s:
        if user:
            s.starttls()
            s.login(user, password or "")
        s.send_message(msg)


COLORS = {"OK": "34",  # blue
          "REVOKED": "31", "INVALID": "31", "EXPIRED": "31", "INCOMPLETE_CHAIN": "31",  # red
          "WARNING": "33", "ERROR": "33", "DNS_ERROR": "33"}  # yellow


def colorize(label):
    """Wrap the label in ANSI color, only when writing to a terminal (not logs/pipes)."""
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
        return label
    return f"\033[1;{COLORS.get(label.strip(), '0')}m{label}\033[0m"


def load_sites(args):
    sites = list(args.sites)
    if args.file:
        with open(args.file) as fh:
            sites += [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    return sites


def short(text, limit):
    return text if len(text) <= limit else text[:limit - 1] + "…"


def print_table(results):
    """Print results as a boxed table; the status cell is colored but padded on its plain width."""
    headers = ["STATUS", "HOST", "EXPIRES", "DAYS", "ISSUER", "DETAILS"]
    rows = [[r["status"], f"{r['host']}:{r['port']}", r["expires"] or "-",
             "-" if r["days_left"] is None else str(r["days_left"]),
             short(r["issuer"], 40) or "-",
             "valid" if r["status"] == "OK" else short(r["message"], 60) or "-"] for r in results]
    widths = [max(len(x) for x in col) for col in zip(headers, *rows)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(cells, colored=False):
        parts = []
        for i, (c, w) in enumerate(zip(cells, widths)):
            pad = c.ljust(w)
            parts.append(" " + (colorize(pad) if colored and i == 0 else pad) + " ")
        return "|" + "|".join(parts) + "|"

    print(line)
    print(fmt(headers))
    print(line)
    for row in rows:
        print(fmt(row, colored=True))
    print(line)
    for r in results:
        if r["cert_file"]:
            print(f"certificate saved: {r['cert_file']} (+ decoded .txt)")


def load_state(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}  # missing or corrupt: treat as a first run


def save_state(path, state):
    """Atomic write so a crash mid-save cannot corrupt the state file."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".ssl_state_")
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, path)


def detect_changes(results, state):
    """Compare results with the saved state. Returns list of (result, headline) for hosts that changed.

    Changed means: status differs (OK->REVOKED, EXPIRED->OK, ...), the certificate itself was
    replaced (new fingerprint), or a problem was seen on the very first run. Day counters and
    message text are ignored, so 'expires in 9 days' -> 'expires in 8 days' is not a change.
    """
    changes = []
    for r in results:
        key = f"{r['host']}:{r['port']}"
        old = state.get(key)
        if old is None:
            if r["status"] != "OK":
                changes.append((r, f"NEW PROBLEM: {r['status']}"))
        elif old["status"] != r["status"]:
            kind = "RECOVERED" if r["status"] == "OK" else "CHANGED"
            changes.append((r, f"{kind}: {old['status']} -> {r['status']}"))
        elif old.get("fingerprint") and r["fingerprint"] and old["fingerprint"] != r["fingerprint"]:
            changes.append((r, "CERTIFICATE REPLACED (new certificate, expires "
                               f"{r['expires']}, was {old.get('expires')})"))
    return changes


def notify(args, text):
    """Send text to every webhook/email. Returns True if nothing was configured or at least one succeeded."""
    ok, tried = False, False
    for url in webhook_urls(args):
        tried = True
        try:
            send_webhook(url, text)
            ok = True
        except Exception as e:
            # don't print the URL: it may contain a bot token
            print(f"webhook failed ({url.split('://')[0]}): {type(e).__name__}: {e}", file=sys.stderr)
    if args.email:
        tried = True
        try:
            send_email(args.email, "SSL certificate change", text,
                       args.smtp_host, args.smtp_port, args.smtp_user, args.smtp_pass)
            ok = True
        except Exception as e:
            print(f"email failed: {e}", file=sys.stderr)
    return ok or not tried


def run_once(args):
    """Check all sites once, print results, send alerts. Returns the list of results."""
    sites = load_sites(args)  # re-read each run so edits to the sites file are picked up
    with ThreadPoolExecutor(max_workers=min(20, len(sites))) as pool:
        results = list(pool.map(lambda s: check(s, args.timeout, args.warn_days, args.dump_cert, args.check_revocation), sites))

    state = load_state(args.state_file)
    changes = detect_changes(results, state)
    first_run = not state

    if args.verbose or first_run or changes:
        print(f"=== {datetime.now():%Y-%m-%d %H:%M:%S} ===", flush=True)
        print_table(results)
    if changes:
        for r, headline in changes:
            print(f"{datetime.now():%H:%M:%S} {headline}: {r['host']}:{r['port']} - {r['message']}", flush=True)

    delivered = True
    if changes:
        text = "SSL certificate change:\n" + "\n".join(
            f"- {headline}: {r['host']}:{r['port']} - {r['message']}"
            + (f" (issuer: {r['issuer']})" if r["issuer"] else "") for r, headline in changes)
        delivered = notify(args, text)

    # Remember the new state. If every alert channel failed, keep the old state of the changed
    # hosts so the change is reported again on the next run instead of being lost.
    changed_keys = {f"{r['host']}:{r['port']}" for r, _ in changes}
    for r in results:
        key = f"{r['host']}:{r['port']}"
        if delivered or key not in changed_keys:
            state[key] = {"status": r["status"], "fingerprint": r["fingerprint"],
                          "expires": r["expires"], "issuer": r["issuer"], "message": r["message"],
                          "checked": datetime.now().isoformat(timespec="seconds")}
    try:
        save_state(args.state_file, state)
    except OSError as e:
        print(f"could not save state file: {e}", file=sys.stderr)
    return results


def parse_duration(value):
    m = re.fullmatch(r"(\d+)([smhd])", value.strip().lower())
    if not m or int(m.group(1)) == 0:
        raise argparse.ArgumentTypeError(f"invalid duration '{value}' (use e.g. 30s, 15m, 6h, 1d)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def parse_clock(value):
    try:
        return datetime.strptime(value, "%H:%M").time()
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid time '{value}' (use 24h HH:MM, e.g. 09:30)")


def seconds_until(clock):
    now = datetime.now()
    nxt = now.replace(hour=clock.hour, minute=clock.minute, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return (nxt - now).total_seconds()


def daemonize(log_file, pid_file):
    """Detach from the terminal (double fork); output goes to log_file."""
    if os.fork() > 0:
        return True  # original process
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    log = open(log_file, "a", buffering=1)
    devnull = open(os.devnull)
    os.dup2(devnull.fileno(), 0)
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)
    sys.stdout = sys.stderr = log
    with open(pid_file, "w") as fh:
        fh.write(str(os.getpid()))
    return False


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("sites", nargs="*", help="hostnames or URLs (host[:port])")
    p.add_argument("-f", "--file", help="file with one site per line (# comments allowed)")
    p.add_argument("-w", "--warn-days", type=int, default=14, help="warn if expiring within N days (default 14)")
    p.add_argument("-t", "--timeout", type=float, default=10)
    p.add_argument("--dump-cert", nargs="?", const="certs", metavar="DIR",
                   help="save each site's certificate into DIR (default ./certs) as .pem plus a decoded .txt, even if invalid")
    p.add_argument("--webhook", action="append", metavar="URL",
                   help="webhook URL (repeatable; also env SSL_WEBHOOKS, comma-separated). "
                        "Slack/Discord/Mattermost/Teams URL, or a bot: telegram://BOT_TOKEN@CHAT_ID, "
                        "slack-bot://TOKEN@CHANNEL_ID, discord-bot://TOKEN@CHANNEL_ID, "
                        "matrix://TOKEN@HOMESERVER/ROOM_ID, bale://TOKEN@CHAT_ID, ntfy://TOPIC, "
                        "pushover://APP_TOKEN@USER_KEY, gotify://APP_TOKEN@HOST")
    p.add_argument("--check-revocation", action="store_true",
                   help="also check OCSP/CRL revocation (uses the openssl CLI; browsers do this, Python does not)")
    p.add_argument("--email", help="recipient address for alerts")
    p.add_argument("--smtp-host", default=os.environ.get("SMTP_HOST", "localhost"),
                   help="SMTP server (default: $SMTP_HOST or localhost)")
    p.add_argument("--smtp-port", type=int, default=int(os.environ.get("SMTP_PORT", 587)),
                   help="SMTP port, STARTTLS (default: $SMTP_PORT or 587)")
    p.add_argument("--smtp-user", default=os.environ.get("SMTP_USER"),
                   help="SMTP login (default: $SMTP_USER)")
    p.add_argument("--smtp-pass", default=os.environ.get("SMTP_PASS"),
                   help="SMTP password (default: $SMTP_PASS; prefer the env var, args show up in `ps`)")
    p.add_argument("--state-file", default="ssl_checker.state.json",
                   help="remembers each site's last status/certificate so only CHANGES are reported "
                        "(default ssl_checker.state.json)")
    p.add_argument("--verbose", action="store_true",
                   help="print the full table on every run, not only on first run / changes")
    sched = p.add_argument_group("scheduling")
    when = sched.add_mutually_exclusive_group()
    when.add_argument("--every", type=parse_duration, metavar="DURATION",
                      help="repeat the check at this interval: 30s, 15m, 6h, 1d (first run is immediate)")
    when.add_argument("--at", type=parse_clock, metavar="HH:MM",
                      help="repeat the check every day at this local time (24h)")
    sched.add_argument("--for", dest="run_for", type=parse_duration, metavar="DURATION",
                       help="stop scheduling after this long, e.g. 7d (default: run until killed)")
    sched.add_argument("--background", action="store_true", help="detach and run in the background (Linux/Unix only)")
    sched.add_argument("--log-file", default="ssl_checker.log", help="background output file (default ssl_checker.log)")
    sched.add_argument("--pid-file", default="ssl_checker.pid", help="background PID file (default ssl_checker.pid)")
    args = p.parse_args()

    if not load_sites(args):
        p.error("no sites given")
    if args.run_for and not (args.every or args.at):
        p.error("--for needs --every or --at")

    if args.background and not hasattr(os, "fork"):
        p.error("--background only works on Linux/Unix; run in a terminal or use Task Scheduler instead")
    if args.background:
        args.log_file, args.pid_file = os.path.abspath(args.log_file), os.path.abspath(args.pid_file)
        args.state_file = os.path.abspath(args.state_file)
        if args.file:
            args.file = os.path.abspath(args.file)
        if daemonize(args.log_file, args.pid_file):
            time.sleep(0.3)  # let the child write its pid file
            pid = open(args.pid_file).read() if os.path.exists(args.pid_file) else "?"
            print(f"running in background (pid {pid}), log: {args.log_file}\nstop with: kill {pid}")
            return

    deadline = time.time() + args.run_for if args.run_for else None
    any_problem = False
    try:
        while True:
            if args.at:
                wait = seconds_until(args.at)
                if deadline and time.time() + wait > deadline:
                    break
                time.sleep(wait)
            results = run_once(args)
            any_problem = any(r["status"] != "OK" for r in results)
            broken = [r for r in results if r["status"] in ("DNS_ERROR", "ERROR")]
            if broken and (args.every or args.at):
                print("Stopped: could not reach the following (fix or remove them, then start again):")
                for r in broken:
                    print(f"  - {r['host']}:{r['port']} [{r['status']}] {r['message']}")
                sys.stdout.flush()
                break
            sys.stdout.flush()
            if not (args.every or args.at):
                break
            if args.every:
                if deadline and time.time() + args.every > deadline:
                    break
                time.sleep(args.every)
    except KeyboardInterrupt:
        pass
    sys.exit(1 if any_problem else 0)


if __name__ == "__main__":
    main()
