"""Egress Network Security Firewall and Filtering Proxy.

Blocks:
- Cloud metadata service endpoints (169.254.169.254, fd00:ec2::254, etc.)
- RFC 1918 Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8, ::1)
- Link-local and multicast ranges
- DNS rebinding / SSRF to internal targets
- Unapproved external domains via strict domain allowlist
"""

import asyncio
import ipaddress
import logging
import os
import socket
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from runtime.config import settings

logger = logging.getLogger("sandbox.egress_firewall")


class EgressFirewall:
    """Core network isolation rules engine evaluating target hosts and IPs."""

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        blocked_cidrs: Optional[List[str]] = None,
        metadata_ips: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
    ):
        self.allowed_domains: Set[str] = {
            d.lower().strip() for d in (allowed_domains or settings.DEFAULT_ALLOWED_DOMAINS)
        }
        self.blocked_domains: Set[str] = {
            d.lower().strip() for d in (blocked_domains or settings.BLOCKED_DOMAINS)
        }
        self.metadata_ips: Set[str] = set(metadata_ips or settings.METADATA_IPS)

        # Pre-parse blocked CIDRs
        raw_cidrs = blocked_cidrs or settings.BLOCKED_CIDRS
        self.blocked_networks: List[ipaddress._BaseNetwork] = []
        for cidr in raw_cidrs:
            try:
                self.blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning(f"Invalid CIDR pattern: {cidr}")

    def is_ip_blocked(self, ip_str: str) -> Tuple[bool, str]:
        """Check if an IPv4 or IPv6 address violates egress security policies."""
        cleaned_ip = ip_str.strip().strip("[]")

        # 1. Direct metadata IP match
        if cleaned_ip in self.metadata_ips:
            return True, f"BLOCKED: Cloud Metadata Service IP ({cleaned_ip})"

        try:
            ip_obj = ipaddress.ip_address(cleaned_ip)
        except ValueError:
            return True, f"BLOCKED: Invalid IP address format ({cleaned_ip})"

        # 2. Inherent dangerous IP properties
        if ip_obj.is_loopback:
            return True, f"BLOCKED: Loopback IP ({cleaned_ip})"
        if ip_obj.is_private:
            return True, f"BLOCKED: RFC 1918 Private IP ({cleaned_ip})"
        if ip_obj.is_link_local:
            return True, f"BLOCKED: Link-Local IP ({cleaned_ip})"
        if ip_obj.is_multicast:
            return True, f"BLOCKED: Multicast IP ({cleaned_ip})"
        if ip_obj.is_reserved:
            return True, f"BLOCKED: Reserved IP ({cleaned_ip})"
        if ip_obj.is_unspecified:
            return True, f"BLOCKED: Unspecified IP ({cleaned_ip})"

        # 3. Explicit CIDR matches
        for net in self.blocked_networks:
            if ip_obj in net:
                return True, f"BLOCKED: Matches restricted subnet {net} ({cleaned_ip})"

        return False, "ALLOWED"

    def is_host_allowed(
        self,
        host: str,
        custom_allowed_domains: Optional[List[str]] = None,
        resolve_dns: bool = True
    ) -> Tuple[bool, str]:
        """Validate target hostname or IP against policies and DNS rebinding protections."""
        cleaned_host = host.split(":")[0].strip().strip("[]").lower()
        if not cleaned_host:
            return True, "BLOCKED: Empty host"

        # Check blocked domain blacklist
        if cleaned_host in self.blocked_domains:
            return True, f"BLOCKED: Prohibited metadata/internal domain ({cleaned_host})"

        # Check if the host is directly an IP literal
        try:
            ipaddress.ip_address(cleaned_host)
            # Host is an IP
            blocked, reason = self.is_ip_blocked(cleaned_host)
            if blocked:
                return True, reason
            # Direct IP access to external hosts is disallowed unless domains are configured
            effective_allowed = {
                d.lower() for d in (custom_allowed_domains or self.allowed_domains)
            }
            if effective_allowed and cleaned_host not in effective_allowed:
                return True, f"BLOCKED: Direct IP connections prohibited without domain allowlist match ({cleaned_host})"
            return False, "ALLOWED"
        except ValueError:
            # Host is a DNS domain name
            pass

        # Validate domain against allowlist
        effective_allowed = {
            d.lower() for d in (custom_allowed_domains or self.allowed_domains)
        }

        matched = False
        for allowed in effective_allowed:
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if cleaned_host == suffix or cleaned_host.endswith("." + suffix):
                    matched = True
                    break
            elif cleaned_host == allowed or cleaned_host.endswith("." + allowed):
                matched = True
                break

        if not matched:
            return True, f"BLOCKED: Domain '{cleaned_host}' is not in approved allowlist ({sorted(effective_allowed)})"

        # Anti-SSRF / DNS Rebinding check: Resolve domain and verify resolved IPs
        if resolve_dns:
            try:
                addr_info = socket.getaddrinfo(cleaned_host, None)
                resolved_ips = {item[4][0] for item in addr_info}
                for resolved_ip in resolved_ips:
                    blocked, reason = self.is_ip_blocked(resolved_ip)
                    if blocked:
                        return True, f"BLOCKED (SSRF Protection): Domain '{cleaned_host}' resolved to restricted IP {resolved_ip} ({reason})"
            except socket.gaierror as e:
                return True, f"BLOCKED: DNS resolution failure for '{cleaned_host}': {e}"

        return False, "ALLOWED"

    def validate_url(
        self,
        url: str,
        custom_allowed_domains: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """Validate URL destination."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path
            return self.is_host_allowed(host, custom_allowed_domains)
        except Exception as e:
            return True, f"BLOCKED: Malformed URL '{url}': {e}"


class EgressProxyServer:
    """Lightweight asynchronous HTTP/HTTPS forward proxy enforcing egress policies."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        firewall: Optional[EgressFirewall] = None
    ):
        self.host = host
        self.port = port
        self.firewall = firewall or EgressFirewall()
        self._server: Optional[asyncio.Server] = None
        self.violation_count = 0

    async def start(self) -> None:
        """Start proxy server."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info(f"Egress filtering proxy active on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop proxy server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Egress proxy stopped")

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """Process incoming client request (CONNECT or regular HTTP)."""
        try:
            line = await client_reader.readline()
            if not line:
                client_writer.close()
                await client_writer.wait_closed()
                return

            request_line = line.decode("latin1", errors="replace").strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                client_writer.close()
                return

            method, target = parts[0].upper(), parts[1]

            # Determine destination host and port
            if method == "CONNECT":
                # HTTPS Tunneling
                if ":" in target:
                    dst_host, dst_port_str = target.split(":", 1)
                    dst_port = int(dst_port_str)
                else:
                    dst_host, dst_port = target, 443
            else:
                # Regular HTTP
                parsed = urlparse(target)
                dst_host = parsed.hostname or target
                dst_port = parsed.port or 80

            # Security Policy Evaluation
            blocked, reason = self.firewall.is_host_allowed(dst_host)
            if blocked:
                self.violation_count += 1
                logger.warning(f"Egress Proxy blocked request to {dst_host}:{dst_port}: {reason}")
                error_body = (
                    f"HTTP/1.1 403 Forbidden\r\n"
                    f"Content-Type: text/plain\r\n"
                    f"X-Sandbox-Egress-Violation: true\r\n"
                    f"Connection: close\r\n\r\n"
                    f"Sandbox Egress Policy Denied: {reason}\n"
                ).encode("utf-8")
                client_writer.write(error_body)
                await client_writer.drain()
                client_writer.close()
                await client_writer.wait_closed()
                return

            # Relaying allowed traffic
            try:
                remote_reader, remote_writer = await asyncio.open_connection(dst_host, dst_port)
            except Exception as e:
                logger.error(f"Failed to connect to upstream {dst_host}:{dst_port}: {e}")
                error_body = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nUpstream connection failed\n"
                client_writer.write(error_body)
                await client_writer.drain()
                client_writer.close()
                return

            if method == "CONNECT":
                # Consume remaining headers
                while True:
                    hdr = await client_reader.readline()
                    if not hdr or hdr == b"\r\n":
                        break
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
            else:
                # Forward original request line
                remote_writer.write(line)
                await remote_writer.drain()

            # Pipe traffic bidirectionally
            await asyncio.gather(
                self._pipe(client_reader, remote_writer),
                self._pipe(remote_reader, client_writer),
                return_exceptions=True
            )

        except Exception as e:
            logger.debug(f"Proxy client handling exception: {e}")
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Stream data between sockets until EOF."""
        try:
            while True:
                data = await reader.read(32768)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


if __name__ == "__main__":
    host = os.environ.get("EGRESS_PROXY_HOST", "0.0.0.0")
    port = int(os.environ.get("EGRESS_PROXY_PORT", "8080"))
    logging.basicConfig(level=logging.INFO)
    print(f"Starting standalone Egress Firewall Proxy on {host}:{port}...")

    server = EgressProxyServer(host=host, port=port)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(server.start())
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(server.stop())

