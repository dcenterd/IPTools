#!/usr/bin/env python3
# Written by Zareh
# Gifted to Seyed Mesbah Ahmadi
"""Check SSL certificate validity/expiry for one or many websites and alert on problems.

Usage:
  ssl_checker.py example.com https://github.com:443
  ssl_checker.py -f sites.txt --warn-days 30
  ssl_checker.py -f sites.txt --webhook https://hooks.slack.com/services/XXX
  ssl_checker.py -f sites.txt --email you@example.com --smtp-host smtp.gmail.com \\
      --smtp-port 587 --smtp-user you@gmail.com --smtp-pass APP_PASSWORD

Run repeatedly / in the background:
  ssl_checker.py -f sites.txt --every 6h --background       (every 6 hours, until killed)
  ssl_checker.py -f sites.txt --at 09:00 --for 30d --background   (daily at 09:00 for 30 days)

NOTE: --background only works on Linux/Unix (it uses fork). On Windows, run the script in a
foreground terminal or use Task Scheduler instead.

Exit code: 0 = all OK, 1 = at least one WARNING/EXPIRED/INVALID/ERROR.
Suitable for cron:  0 */6 * * * /usr/bin/python3 /path/ssl_checker.py -f sites.txt --webhook URL

The --smtp-* flags default to the env vars SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS.
Optional sender address: SMTP_FROM (defaults to the SMTP user).
"""
import argparse
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlparse


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
    return {"issuer": format_issuer(issuer), "expires": expires}


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


def check(target, timeout, warn_days, dump_dir=None):
    result = _check(target, timeout, warn_days)
    result["cert_file"] = ""
    if dump_dir and result["host"] and result["status"] not in ("DNS_ERROR", "ERROR"):
        result["cert_file"] = dump_cert(result["host"], result["port"], timeout, dump_dir)
    return result


def _check(target, timeout, warn_days):
    host, port = parse_target(target)
    result = {"target": target, "host": host, "port": port, "status": "OK",
              "days_left": None, "expires": None, "issuer": "", "message": ""}
    if not host:
        result.update(status="ERROR", message="could not parse host")
        return result

    ctx = ssl.create_default_context()  # verifies chain + hostname
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
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
        status = "INCOMPLETE_CHAIN" if e.verify_code == 20 else "INVALID"
        message = e.verify_message or str(e)
        if status == "INCOMPLETE_CHAIN":
            message += " (server is not sending the intermediate certificate)"
        result.update(status=status, message=message)
        info = inspect_unverified(host, port, timeout)
        if info:
            result.update(issuer=info["issuer"], expires=info["expires"].strftime("%Y-%m-%d"),
                          days_left=(info["expires"] - datetime.now(timezone.utc)).days)
    except ssl.SSLError as e:
        result.update(status="INVALID", message=f"SSL error: {e}")
    except (socket.timeout, TimeoutError):
        result.update(status="ERROR", message="connection timed out")
    except socket.gaierror as e:
        result.update(status="DNS_ERROR", message=f"DNS lookup failed, domain does not resolve ({e.strerror})")
    except OSError as e:
        result.update(status="ERROR", message=f"connection failed: {e}")
    return result


def send_webhook(url, text):
    # {"text": ...} works for Slack and Mattermost; Discord wants "content", so send both.
    body = json.dumps({"text": text, "content": text}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10).close()


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
          "INVALID": "31", "EXPIRED": "31", "INCOMPLETE_CHAIN": "31",  # red
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


def run_once(args):
    """Check all sites once, print results, send alerts. Returns the list of results."""
    sites = load_sites(args)  # re-read each run so edits to the sites file are picked up
    with ThreadPoolExecutor(max_workers=min(20, len(sites))) as pool:
        results = list(pool.map(lambda s: check(s, args.timeout, args.warn_days, args.dump_cert), sites))

    print_table(results)

    problems = [r for r in results if r["status"] != "OK"]
    if problems:
        text = "SSL certificate alert:\n" + "\n".join(
            f"- {r['status']}: {r['host']}:{r['port']} - {r['message']}"
            + (f" (issuer: {r['issuer']})" if r["issuer"] else "") for r in problems)
        if args.webhook:
            try:
                send_webhook(args.webhook, text)
            except Exception as e:
                print(f"webhook failed: {e}", file=sys.stderr)
        if args.email:
            try:
                send_email(args.email, f"SSL alert: {len(problems)} problem(s)", text,
                           args.smtp_host, args.smtp_port, args.smtp_user, args.smtp_pass)
            except Exception as e:
                print(f"email failed: {e}", file=sys.stderr)
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
    p.add_argument("--webhook", help="Slack/Discord/Mattermost webhook URL for alerts")
    p.add_argument("--email", help="recipient address for alerts")
    p.add_argument("--smtp-host", default=os.environ.get("SMTP_HOST", "localhost"),
                   help="SMTP server (default: $SMTP_HOST or localhost)")
    p.add_argument("--smtp-port", type=int, default=int(os.environ.get("SMTP_PORT", 587)),
                   help="SMTP port, STARTTLS (default: $SMTP_PORT or 587)")
    p.add_argument("--smtp-user", default=os.environ.get("SMTP_USER"),
                   help="SMTP login (default: $SMTP_USER)")
    p.add_argument("--smtp-pass", default=os.environ.get("SMTP_PASS"),
                   help="SMTP password (default: $SMTP_PASS; prefer the env var, args show up in `ps`)")
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
            print(f"=== {datetime.now():%Y-%m-%d %H:%M:%S} ===", flush=True)
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
