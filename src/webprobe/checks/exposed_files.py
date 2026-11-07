from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from webprobe.checks.base import Check
from webprobe.client import Response
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

MAX_BYTES = 64_000
SECRET_WORDS = rb"(?i)(pass(word)?|secret|token|api_?key|private_?key|aws_|database_url|dsn)"
REDACT_RE = re.compile(r"(?i)((?:pass|secret|token|key|pwd|auth|dsn|url)[^\n=:]{0,30}[=:]\s*[\"']?)([^\s\"']{1,3})[^\s\"']*")
# define('DB_PASSWORD', '...') / define('AUTH_KEY', '...') in wp-config.php
DEFINE_RE = re.compile(r"(?i)(define\s*\(\s*([\"'])\w*(?:pass|secret|token|key|salt)\w*\2\s*,\s*([\"']))([^\"']{1,3})[^\"']*")
# Whole PEM/OpenSSH private key blocks, END marker optional (the body may be truncated).
PRIVATE_KEY_RE = re.compile(r"(-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----)(.*?)(?:(-----END \2PRIVATE KEY-----)|\Z)", re.S)
HTPASSWD_SIG = rb"(?m)^[^:\s]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)"
# user:hash -> keep the user and the hash scheme, drop the hash itself
HTPASSWD_LINE_RE = re.compile(r"^([^:\s]+:)(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)?\S+$")


@dataclass(frozen=True, slots=True)
class SensitivePath:
    paths: tuple[str, ...]
    title: str
    severity: Severity
    signature: re.Pattern[bytes]  # body must match: no signature match, no finding
    description: str
    escalate_if: re.Pattern[bytes] | None = None  # bump to CRITICAL when this also matches


def _sp(paths, title, severity, signature, description, escalate_if=None) -> SensitivePath:
    return SensitivePath(
        tuple(paths.split()), title, severity, re.compile(signature), description,
        re.compile(escalate_if) if escalate_if else None,
    )


SENSITIVE_PATHS = [
    _sp(".git/HEAD", "Git repository exposed", Severity.HIGH, rb"^(ref: refs/|[0-9a-f]{40}\s*$)",
        "The .git directory is web-accessible. Tools like git-dumper can rebuild the full source code and history, often including secrets."),
    _sp(".git/config", "Git configuration exposed", Severity.HIGH, rb"\[core\]",
        "The .git/config file is readable; it may contain remote URLs with embedded credentials."),
    _sp(".svn/wc.db", "Subversion repository exposed", Severity.HIGH, rb"^SQLite format 3",
        "The SVN working-copy database is downloadable, revealing file listings and source."),
    _sp(".hg/requires", "Mercurial repository exposed", Severity.HIGH, rb"revlogv1|fncache|dotencode",
        "The .hg directory is web-accessible, allowing source code recovery."),
    _sp(".env .env.local .env.production .env.backup", "Environment file exposed", Severity.HIGH,
        rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", "A dotenv file with application configuration is publicly readable.",
        escalate_if=SECRET_WORDS),
    _sp(".aws/credentials", "AWS credentials file exposed", Severity.CRITICAL, rb"aws_access_key_id",
        "AWS access keys are publicly readable."),
    _sp("id_rsa .ssh/id_rsa id_ed25519", "Private SSH key exposed", Severity.CRITICAL,
        rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "A private SSH key is publicly downloadable."),
    _sp(".htpasswd", "htpasswd file exposed", Severity.HIGH,
        HTPASSWD_SIG, "Password hashes for HTTP basic auth are downloadable and can be cracked offline."),
    _sp(".npmrc", "npm credentials exposed", Severity.HIGH, rb"_auth(?:Token)?\s*=",
        "An .npmrc with registry auth tokens is publicly readable."),
    _sp(".vscode/sftp.json", "Editor SFTP config exposed", Severity.HIGH, rb"\"(?:password|privateKeyPath)\"",
        "An SFTP deployment config (often containing server credentials) is publicly readable."),
    _sp("wp-config.php.bak wp-config.php~ wp-config.php.save wp-config.old", "WordPress config backup exposed",
        Severity.CRITICAL, rb"DB_PASSWORD", "A backup of wp-config.php is served as plain text, disclosing database credentials and auth salts."),
    _sp("config.php.bak config.php~ index.php.bak", "PHP source backup exposed", Severity.HIGH, rb"<\?php",
        "A PHP backup file is served as plain text instead of being executed, disclosing source code."),
    _sp("backup.zip site.zip www.zip backup.tar.gz", "Backup archive exposed", Severity.HIGH, rb"^(PK\x03\x04|\x1f\x8b)",
        "A backup archive is downloadable and likely contains source code and configuration."),
    _sp("backup.sql dump.sql database.sql db.sql", "SQL dump exposed", Severity.HIGH,
        rb"(?i)(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", "A database dump is publicly downloadable."),
    _sp("phpinfo.php info.php", "phpinfo() page exposed", Severity.MEDIUM, rb"<title>PHP \d|phpinfo\(\)",
        "phpinfo() reveals PHP version, modules, paths and environment variables."),
    _sp("server-status", "Apache server-status exposed", Severity.MEDIUM, rb"Apache Server Status",
        "mod_status reveals current requests, client IPs and internal URLs."),
    _sp("server-info", "Apache server-info exposed", Severity.MEDIUM, rb"Apache Server Information",
        "mod_info reveals the full server configuration."),
    _sp("actuator/env", "Spring Boot actuator /env exposed", Severity.HIGH, rb"\"(?:propertySources|activeProfiles)\"",
        "The actuator env endpoint leaks configuration properties, often including credentials."),
    _sp("actuator/heapdump", "Spring Boot heap dump exposed", Severity.CRITICAL, rb"^JAVA PROFILE 1\.0\.[12]",
        "A JVM heap dump is downloadable; it contains in-memory secrets, sessions and credentials."),
    _sp("web.config", "IIS web.config exposed", Severity.MEDIUM, rb"<configuration",
        "The IIS configuration file is readable and may contain connection strings."),
    _sp("docker-compose.yml docker-compose.yaml", "docker-compose file exposed", Severity.LOW, rb"(?m)^services:",
        "Infrastructure configuration is disclosed; check it for embedded secrets."),
    _sp("crossdomain.xml", "Permissive crossdomain.xml", Severity.LOW, rb"allow-access-from\s+domain=\"\*\"",
        "Any Flash/Silverlight origin may read responses from this site."),
]


def _redact_private_key(match: re.Match[str]) -> str:
    begin, _, key_body, end = match.groups()
    size = len(key_body.strip().encode())
    return f"{begin}\n[{size} bytes of key material redacted]\n{end or '(no END marker in the downloaded part)'}"


def evidence_from(body: bytes) -> str:
    head = body[:512]
    if b"\x00" in head:
        return f"{len(body)}+ bytes, starts with {body[:8]!r}"
    text = PRIVATE_KEY_RE.sub(_redact_private_key, body.decode("utf-8", errors="replace"))
    htpasswd = re.search(HTPASSWD_SIG, body) is not None
    out = []
    for line in text.splitlines()[:6]:
        if htpasswd:
            line = HTPASSWD_LINE_RE.sub(r"\1\2****", line)
        line = DEFINE_RE.sub(r"\1\4****", line)
        out.append(REDACT_RE.sub(r"\1\2****", line)[:160])
    return "\n".join(out)


class ExposedFilesCheck(Check):
    id = "exposed-files"
    name = "Exposed sensitive files"
    description = "VCS directories, dotenv files, backups, keys and debug endpoints (content-verified)."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        jobs = [(item, path) for item in SENSITIVE_PATHS for path in item.paths]
        responses = await asyncio.gather(*(ctx.client.fetch(path, max_bytes=MAX_BYTES) for _, path in jobs))
        findings = []
        for (item, _), response in zip(jobs, responses):
            if response is not None and self._confirmed(item, response):
                findings.append(self._report(item, response))
        return findings

    @staticmethod
    def _confirmed(item: SensitivePath, response: Response) -> bool:
        # Signature matching (not status codes) is what keeps soft-404s from producing noise.
        return response.status in (200, 206) and bool(item.signature.search(response.content))

    def _report(self, item: SensitivePath, response: Response) -> Finding:
        severity = item.severity
        if item.escalate_if is not None and item.escalate_if.search(response.content):
            severity = Severity.CRITICAL
        return self.finding(
            item.title, severity, response.url, item.description,
            evidence=evidence_from(response.content),
            remediation="Remove the file from the web root and block access to dotfiles/backups at the web server. "
                        "Treat any credentials it contained as compromised and rotate them.",
        )
