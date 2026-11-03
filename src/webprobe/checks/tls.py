from __future__ import annotations

import asyncio
import socket
import ssl
import time
import warnings

import httpx

from webprobe.checks.base import Check
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

LEGACY_PROTOCOLS = (("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"))


def _handshake(host: str, port: int, context: ssl.SSLContext, timeout: float) -> tuple[str | None, dict, tuple]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version(), tls.getpeercert() or {}, tls.cipher() or ("", "", 0)


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _supports(host: str, port: int, version_name: str, timeout: float) -> bool:
    """Try a handshake pinned to one legacy protocol version."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        version = getattr(ssl.TLSVersion, version_name)
        context = _unverified_context()
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
            context.minimum_version = version
            context.maximum_version = version
            _handshake(host, port, context, timeout)
        except (OSError, ValueError, ssl.SSLError):
            # Note: also False if the local OpenSSL build can't speak this version.
            return False
    return True


class TLSCheck(Check):
    id = "tls"
    name = "TLS / HTTPS configuration"
    description = "Certificate validity and expiry, legacy protocol support, HTTP->HTTPS redirect."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        url = httpx.URL(ctx.target)
        if url.scheme != "https":
            return [self.finding(
                "Site served over plain HTTP", Severity.MEDIUM, ctx.target,
                "Traffic, including credentials and session cookies, can be read and modified by anyone on the network path.",
                remediation="Serve the site over HTTPS only and redirect HTTP to HTTPS.",
            )]

        host, port = url.host, url.port or 443
        timeout = ctx.client.config.timeout
        findings: list[Finding] = []

        try:
            version, cert, cipher = await asyncio.to_thread(_handshake, host, port, ssl.create_default_context(), timeout)
        except ssl.SSLCertVerificationError as exc:
            findings.append(self.finding(
                "TLS certificate is not trusted", Severity.HIGH, ctx.target,
                "Browsers will show a certificate error. Users who click through are open to man-in-the-middle attacks.",
                evidence=exc.verify_message or str(exc),
                remediation="Install a certificate from a trusted CA that matches the hostname and is within its validity period.",
            ))
            try:
                version, cert, cipher = await asyncio.to_thread(_handshake, host, port, _unverified_context(), timeout)
            except (OSError, ssl.SSLError):
                return findings
        except (OSError, ssl.SSLError) as exc:
            raise RuntimeError(f"TLS handshake with {host}:{port} failed: {exc}") from exc

        if cert.get("notAfter"):
            days_left = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
            if days_left <= 30:
                findings.append(self.finding(
                    f"TLS certificate expires in {days_left} days", Severity.MEDIUM if days_left <= 7 else Severity.LOW,
                    ctx.target, "The certificate is close to expiry; once expired, browsers will block the site.",
                    evidence=f"notAfter: {cert['notAfter']}",
                    remediation="Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt).",
                ))

        if cipher and cipher[2] and cipher[2] < 128:
            findings.append(self.finding(
                "Weak TLS cipher negotiated", Severity.MEDIUM, ctx.target,
                f"The server negotiated a {cipher[2]}-bit cipher by default.",
                evidence=f"{version} {cipher[0]}", remediation="Disable ciphers below 128 bits.",
            ))

        legacy = await asyncio.gather(*(
            asyncio.to_thread(_supports, host, port, attr, timeout) for _, attr in LEGACY_PROTOCOLS
        ))
        for (label, _), supported in zip(LEGACY_PROTOCOLS, legacy):
            if supported:
                findings.append(self.finding(
                    f"Deprecated protocol {label} supported", Severity.MEDIUM, ctx.target,
                    f"{label} is deprecated (RFC 8996) and has known weaknesses; it is also an audit failure under PCI DSS.",
                    remediation="Allow only TLS 1.2 and TLS 1.3.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                ))

        findings.append(self.finding(
            "TLS configuration summary", Severity.INFO, ctx.target,
            "Protocol and cipher negotiated with default client settings.",
            evidence=f"{version} {cipher[0]} ({cipher[2]} bits)",
        ))

        findings += await self._http_redirect(ctx, host)
        return findings

    async def _http_redirect(self, ctx: ScanContext, host: str) -> list[Finding]:
        plain = f"http://{host}/"
        # Same host, different scheme: deliberately outside the strict origin scope.
        try:
            response = await ctx.client.request("GET", plain, enforce_scope=False, max_bytes=4096)
        except httpx.HTTPError:
            return []  # nothing listening on port 80 is fine
        location = response.location or ""
        if response.is_redirect and location.startswith("https://"):
            return []
        return [self.finding(
            "HTTP does not redirect to HTTPS", Severity.LOW, plain,
            "Users who type the bare domain land on an unencrypted page.",
            evidence=f"HTTP {response.status}" + (f" -> {location}" if location else ""),
            remediation="Return a 301 redirect from http:// to https:// for every path.",
        )]
