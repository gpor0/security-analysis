#!/usr/bin/env python3
"""
Port scanner for authorized security assessment.

Usage:
    python portscan.py -t example.com 192.168.1.1
    python portscan.py -f targets.txt -p 1-1024 --json report.json
    python portscan.py -t 10.0.0.1 -p common --timeout 1.5 --workers 200

Only scan systems you own or have explicit written authorization to test.
Unauthorized port scanning may violate computer-misuse laws in your jurisdiction.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import html
import ipaddress
import json
import socket
import ssl
import sys
from pathlib import Path
from typing import Iterable


# A practical "top ports" list — covers the services most pen tests care about.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 902,
    993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 2082, 2083,
    2222, 2375, 2376, 2483, 2484, 3128, 3268, 3269, 3306, 3389, 4369, 4444,
    4848, 5000, 5060, 5061, 5222, 5432, 5601, 5672, 5900, 5984, 5985, 5986,
    6379, 6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669,
    7000, 7001, 7002, 7077, 7199, 7474, 8000, 8008, 8009, 8080, 8081, 8086,
    8088, 8089, 8161, 8200, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9100,
    9200, 9300, 9418, 9600, 9999, 10000, 11211, 15672, 25565, 27017, 27018,
    27019, 28015, 50000, 50070, 50075, 61616,
]

# Kubernetes / container-orchestration ecosystem ports.
# Control plane, worker components, CNI plugins, service mesh sidecars,
# common ingress controllers, and the apps you typically find inside clusters
# (registries, observability, message brokers, databases).
KUBERNETES_PORTS = [
    # --- Control plane ---
    2379, 2380,          # etcd client / peer
    6443,                # kube-apiserver (default secure)
    8443,                # kube-apiserver (alt) / many webhook servers
    10257,               # kube-controller-manager (secure)
    10259,               # kube-scheduler (secure)
    # --- Worker node components ---
    10248,               # kubelet healthz
    10250,               # kubelet API
    10255,               # kubelet read-only (deprecated; still seen in legacy)
    10256,               # kube-proxy health
    # --- Container runtimes exposed over TCP (misconfig risk) ---
    2375, 2376,          # Docker daemon plain / TLS
    4243, 4244,          # legacy Docker swarm
    # --- CNI / cluster networking ---
    179,                 # BGP (Calico, Cilium)
    4240,                # Cilium health
    4789,                # VXLAN (Flannel, Calico VXLAN)
    8285, 8472,          # Flannel UDP / VXLAN
    9099,                # Calico Felix health
    # --- Service mesh (Istio, Linkerd) ---
    4140, 4143, 4191,    # Linkerd proxy / admin
    15000, 15001, 15006, 15008, 15009, 15010,  # Envoy admin / Istio xDS
    15012, 15014, 15017, 15020, 15021, 15090,  # Istiod / sidecar / metrics
    # --- Ingress / API gateways ---
    8001,                # Kong admin / kubectl proxy
    8444,                # NGINX ingress alt
    18080, 18443,        # commonly remapped HTTP/HTTPS
    # --- Container registries ---
    5000,                # Docker Registry v2
    5001,                # Harbor / Registry alt
    # --- Observability ---
    3000,                # Grafana
    3100,                # Loki
    4317, 4318,          # OpenTelemetry gRPC / HTTP
    5044,                # Logstash beats
    5601,                # Kibana
    8125,                # statsd
    8428,                # VictoriaMetrics
    9090,                # Prometheus
    9091,                # Pushgateway / Traefik metrics
    9093,                # Alertmanager
    9100,                # node_exporter
    9200, 9300,          # Elasticsearch / OpenSearch
    14250, 14268, 14269, # Jaeger collector
    16686,               # Jaeger UI
    # --- NodePort default range (likely to expose anything) ---
    30000, 30001, 30002, 30003, 31000, 32000,
    # --- Service discovery / config / secrets ---
    2181, 2888, 3888,    # ZooKeeper client / peer / election
    8200, 8201,          # Vault API / cluster
    8500, 8501, 8502, 8600,  # Consul HTTP/HTTPS/gRPC/DNS
    # --- Message brokers ---
    1883, 8883,          # MQTT plain / TLS
    4222, 6222, 8222,    # NATS
    4369, 5672, 15672, 25672,  # RabbitMQ epmd / AMQP / mgmt / clustering
    6379, 16379, 26379,  # Redis / cluster bus / Sentinel
    9092, 9093, 9094,    # Kafka brokers
    # --- Databases commonly run as StatefulSets ---
    3306, 33060,         # MySQL / MySQL X protocol
    5432,                # PostgreSQL
    7000, 7001,          # Cassandra inter-node
    8086, 8088,          # InfluxDB
    9042, 9160,          # Cassandra
    27017, 27018, 27019, # MongoDB
    # --- CI/CD running inside clusters ---
    8080,                # Jenkins / many web UIs
    50000,               # Jenkins JNLP agent
    # --- Misc cloud-native ---
    8181,                # Open Policy Agent
    9000,                # MinIO
    9001,                # MinIO console
    9999,                # Portainer / various
]

# Monitoring / observability tooling ports.
# Covers metrics (Prometheus ecosystem, TSDBs, exporters), logging (ELK,
# Loki, Splunk, Graylog, Fluent), tracing (Jaeger, Zipkin, OpenTelemetry,
# Tempo), APM (Datadog/New Relic/Elastic agents), and the dashboard /
# alerting UIs that sit on top of them. Many overlap with the k8s profile
# since these tools are most often deployed inside clusters.
OBSERVABILITY_PORTS = [
    # --- Metrics: Prometheus ecosystem ---
    9090,                 # Prometheus server
    9091,                 # Pushgateway
    9093, 9094,           # Alertmanager API / cluster gossip
    9100,                 # node_exporter
    9101,                 # haproxy_exporter
    9102,                 # statsd_exporter
    9103,                 # collectd_exporter
    9104,                 # mysqld_exporter
    9105,                 # mesos_exporter
    9106,                 # cloudwatch_exporter
    9107,                 # consul_exporter
    9108,                 # graphite_exporter
    9113,                 # nginx-prometheus-exporter
    9114,                 # elasticsearch_exporter
    9115,                 # blackbox_exporter
    9117,                 # apache_exporter
    9121,                 # redis_exporter
    9150,                 # memcached_exporter
    9182,                 # windows_exporter
    9187,                 # postgres_exporter
    9189,                 # patroni_exporter
    9216,                 # mongodb_exporter
    9256,                 # process_exporter
    9258,                 # hpe-power-exporter / process variants
    9273,                 # telegraf prometheus output
    9419,                 # rabbitmq_exporter
    9540,                 # rabbitmq cluster operator
    9633,                 # ipmi_exporter
    9796,                 # podman_exporter
    9913,                 # nginx vts exporter
    # --- Time-series databases ---
    2003, 2004,           # Graphite plaintext / pickle
    2023, 2024,           # Graphite carbon aggregator
    7002,                 # Carbon-cache query
    8086, 8088,           # InfluxDB HTTP / RPC
    8089,                 # InfluxDB admin (legacy)
    8125,                 # statsd
    8126,                 # statsd admin
    8428,                 # VictoriaMetrics single-node
    8480, 8481, 8482,     # VictoriaMetrics vmselect / vminsert / vmstorage
    4242,                 # OpenTSDB
    8242,                 # OpenTSDB read endpoint
    # --- Logging: ELK / OpenSearch stack ---
    5044,                 # Logstash beats input
    5045,                 # Logstash beats TLS
    5601,                 # Kibana / OpenSearch dashboards
    9200, 9300,           # Elasticsearch / OpenSearch HTTP / transport
    9600,                 # Logstash monitoring API
    9700,                 # Logstash metrics
    # --- Logging: Loki / Grafana stack ---
    3100,                 # Loki HTTP
    3200,                 # Tempo HTTP
    7946,                 # Loki / Tempo memberlist gossip
    9095,                 # Tempo gRPC
    # --- Logging: Splunk ---
    8000,                 # Splunk Web UI
    8088,                 # Splunk HTTP Event Collector (HEC)
    8089,                 # Splunkd management
    8191,                 # Splunk KV store
    9997,                 # Splunk forwarder receiver
    # --- Logging: Graylog ---
    9000,                 # Graylog Web UI
    12201,                # GELF UDP/TCP
    1514,                 # Syslog TLS commonly used by Graylog
    # --- Logging: Fluentd / Fluent Bit / Vector ---
    24220,                # Fluentd monitor_agent
    24224,                # Fluentd forward
    24230,                # Fluentd debug
    2020,                 # Fluent Bit HTTP server
    8686,                 # Vector API
    # --- Tracing ---
    4317, 4318,           # OpenTelemetry OTLP gRPC / HTTP
    5775,                 # Jaeger Zipkin/Thrift UDP (legacy)
    6831, 6832,           # Jaeger agent UDP (compact / binary)
    5778,                 # Jaeger agent config
    14250,                # Jaeger collector gRPC
    14268,                # Jaeger collector HTTP
    14269,                # Jaeger admin
    16685,                # Jaeger query gRPC
    16686,                # Jaeger query UI
    9411,                 # Zipkin
    # --- Dashboards / general UIs ---
    1936,                 # HAProxy stats
    3000,                 # Grafana
    8265,                 # Ray dashboard
    8404,                 # HAProxy stats (alt)
    19999,                # Netdata
    # --- APM agents / collectors ---
    8125, 8126, 8127, 8128,  # Datadog statsd / trace / dogstatsd variants
    8200,                 # Elastic APM server (note: conflicts w/ Vault)
    8126,                 # Datadog APM
    8083,                 # InfluxDB / various agents
    # --- Misc monitoring stacks ---
    1099,                 # JMX RMI registry (Java apps)
    1098,                 # JMX activation
    5555,                 # ManageEngine / various agents
    10050, 10051,         # Zabbix agent / server
    10052, 10053,         # Zabbix TLS variants
    12345,                # NetXMS / monitoring backdoors
    161, 162,             # SNMP / SNMP trap (TCP variants)
    199,                  # SMUX (SNMP multiplexing)
    705,                  # AgentX
    1270,                 # SCOM (Microsoft Operations Manager)
    4505, 4506,           # SaltStack master publish / return
    8140,                 # Puppet master
    9100,                 # Already listed; also Salt
    # --- Sentry / error tracking ---
    9000,                 # Sentry web (also MinIO/Graylog — context matters)
    # --- pprof / Go profiling endpoints (often inadvertently exposed) ---
    6060,                 # net/http/pprof default
    8888,                 # alt pprof / Tornado
]

# Lightweight banner-grab probes per port. None = just connect, don't send.
BANNER_PROBES: dict[int, bytes | None] = {
    21: None,         # FTP banners on connect
    22: None,         # SSH banner on connect
    23: None,         # Telnet
    25: None,         # SMTP
    80: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    110: None,        # POP3
    143: None,        # IMAP
    443: b"",         # TLS handled separately
    465: b"",         # SMTPS
    587: None,        # SMTP submission
    993: b"",         # IMAPS
    995: b"",         # POP3S
    3306: None,       # MySQL banner on connect
    5432: None,       # Postgres (will reject, but we get a response)
    6379: b"*1\r\n$4\r\nPING\r\n",  # Redis
    8080: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8443: b"",        # alt HTTPS
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 5986, 6443, 8883, 10250, 10257, 10259, 2379, 2380, 15021}

# Default User-Agent string for HTTP probes.
# Deliberately distinctive so the operator can filter their own probes out of
# server access logs (e.g. `grep "PortScan-PenTest"` in nginx logs).
# Includes a hostname token so multi-source scans are easy to attribute.
# Override at runtime with --user-agent.
DEFAULT_USER_AGENT = f"PortScan-PenTest/1.0 (authorized-assessment; src={socket.gethostname()})"


@dataclasses.dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered", "error"
    service: str = ""
    banner: str = ""
    tls_info: dict | None = None
    http_info: dict | None = None
    error: str = ""


@dataclasses.dataclass
class HostResult:
    target: str
    resolved_ip: str = ""
    reverse_dns: str = ""
    resolution_error: str = ""
    ports: list[PortResult] = dataclasses.field(default_factory=list)
    scan_started: str = ""
    scan_finished: str = ""

    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]


def parse_port_spec(spec: str) -> list[int]:
    """Parse a port spec into a sorted, deduped port list.

    Accepts:
      * Numeric forms: '22', '22,80,443', '1-1024', '22,80-90,443'
      * Named profiles: 'common', 'top', 'top100', 'kubernetes', 'k8s', 'all'
      * Combinations: 'common+kubernetes', 'k8s,8080,9000-9010'
    """
    spec = spec.strip().lower()
    if not spec:
        raise ValueError("empty port spec")

    profiles = {
        "common": COMMON_PORTS,
        "top": COMMON_PORTS,
        "top100": COMMON_PORTS,
        "kubernetes": KUBERNETES_PORTS,
        "k8s": KUBERNETES_PORTS,
        "observability": OBSERVABILITY_PORTS,
        "monitoring": OBSERVABILITY_PORTS,
        "obs": OBSERVABILITY_PORTS,
        "all": list(range(1, 65536)),
    }

    ports: set[int] = set()
    # Allow '+' or ',' as separators between profiles and numeric chunks.
    for chunk in spec.replace("+", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk in profiles:
            ports.update(profiles[chunk])
        elif "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if not (1 <= lo_i <= hi_i <= 65535):
                raise ValueError(f"Invalid range: {chunk}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            p = int(chunk)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)

    if not ports:
        raise ValueError(f"port spec resolved to no ports: {spec!r}")
    return sorted(ports)


def resolve(target: str) -> tuple[str, str, str]:
    """Return (ip, reverse_dns, error)."""
    try:
        # If it's already a valid IP, skip A-record lookup.
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return "", "", f"DNS resolution failed: {e}"

    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        rdns = ""

    return ip, rdns, ""


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


# TLS versions considered deprecated. The TLS layer reports these as
# protocol strings like "TLSv1", "TLSv1.1", "SSLv3" (Python 3.10+).
DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Cipher fragments that indicate weak crypto even on modern TLS versions.
# Matched case-insensitively as substrings against the cipher name returned
# by ssl.SSLSocket.cipher()[0] (OpenSSL naming, e.g. "ECDHE-RSA-AES128-GCM-SHA256").
WEAK_CIPHER_TOKENS = (
    "NULL", "EXPORT", "RC4", "RC2", "DES-CBC", "3DES", "MD5",
    "ANON", "ADH", "AECDH", "IDEA", "SEED", "PSK-NULL",
)


def _classify_tls(protocol: str, cipher: str) -> tuple[list[str], list[str]]:
    """Return (findings, severity_tags) describing weaknesses in this handshake."""
    findings: list[str] = []
    tags: list[str] = []

    if protocol in DEPRECATED_TLS_VERSIONS:
        findings.append(f"Deprecated TLS version: {protocol} (RFC 8996; below TLS 1.2)")
        tags.append("DEPRECATED_TLS")
    elif protocol == "TLSv1.2":
        # Not deprecated, but call it out so the auditor can chase TLS 1.3 upgrades.
        tags.append("TLS_1_2")
    elif protocol == "TLSv1.3":
        tags.append("TLS_1_3")

    cipher_upper = (cipher or "").upper()
    for token in WEAK_CIPHER_TOKENS:
        if token in cipher_upper:
            findings.append(f"Weak cipher in use: {cipher} (contains {token})")
            tags.append("WEAK_CIPHER")
            break

    return findings, tags


def _tls_handshake(ip: str, port: int, hostname: str, timeout: float,
                   allow_legacy: bool) -> dict:
    """Perform a single TLS handshake. Returns a result dict; never raises."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if allow_legacy:
        # Drop the floor so we can detect servers that ONLY speak TLS 1.0/1.1.
        # Cipher list also has to be widened — OpenSSL's default refuses legacy suites.
        try:
            ctx.minimum_version = ssl.TLSVersion.SSLv3
        except (ValueError, AttributeError):
            pass
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname or None) as tls:
                protocol = tls.version() or ""
                cipher_tuple = tls.cipher() or ("", "", 0)
                cipher_name = cipher_tuple[0] if cipher_tuple else ""

                cert = tls.getpeercert(binary_form=False) or {}
                if not cert:
                    der = tls.getpeercert(binary_form=True)
                    if der:
                        cert = {"raw_der_bytes": len(der)}

                info: dict = {
                    "protocol": protocol,
                    "cipher": cipher_name,
                }
                if cert:
                    subj = cert.get("subject", ())
                    issuer = cert.get("issuer", ())
                    info["subject"] = " ".join(f"{k}={v}" for tup in subj for k, v in tup)
                    info["issuer"] = " ".join(f"{k}={v}" for tup in issuer for k, v in tup)
                    info["not_before"] = cert.get("notBefore", "")
                    info["not_after"] = cert.get("notAfter", "")
                    san = cert.get("subjectAltName", ())
                    if san:
                        info["san"] = [f"{t}:{v}" for t, v in san]
                return info
    except Exception as e:
        return {"error": str(e)}


def grab_tls_info(ip: str, port: int, hostname: str, timeout: float) -> dict | None:
    """Probe TLS on a port, detecting deprecated versions (< TLS 1.2) and weak ciphers.

    Two-stage strategy:
      1. Modern handshake with secure defaults. If it succeeds, report the
         negotiated version and flag if it happens to be TLS 1.0/1.1 (rare —
         most modern OpenSSL builds refuse this — but possible on older Pythons).
      2. If stage 1 fails, retry with the floor dropped to SSLv3 and ciphers
         widened. If THIS succeeds, the server only speaks deprecated TLS — a
         finding in its own right. We attach the modern-handshake error so the
         operator can see why the secure attempt failed.
    """
    info = _tls_handshake(ip, port, hostname, timeout, allow_legacy=False)

    if "error" in info:
        # Retry with legacy support to figure out if the port speaks TLS at all
        # and, if so, what deprecated version it's stuck on.
        modern_error = info["error"]
        legacy = _tls_handshake(ip, port, hostname, timeout, allow_legacy=True)

        if "error" in legacy:
            # Both failed — probably not TLS, or seriously broken.
            return {"error": modern_error, "legacy_error": legacy["error"]}

        # Legacy handshake succeeded → modern was refused → server is on deprecated TLS.
        legacy["modern_handshake_error"] = modern_error
        findings, tags = _classify_tls(legacy.get("protocol", ""), legacy.get("cipher", ""))
        # Even if classify() didn't tag it (e.g. server negotiated TLS 1.2 on the
        # retry for some other reason), the fact that the SECURE attempt failed
        # is itself worth surfacing.
        if not findings:
            findings.append(
                f"Modern TLS handshake failed ({modern_error}); "
                f"only succeeded with legacy settings"
            )
            tags.append("DEPRECATED_TLS")
        legacy["findings"] = findings
        legacy["severity_tags"] = sorted(set(tags))
        return legacy

    # Stage 1 succeeded. Still classify in case TLS 1.0/1.1 was somehow negotiated
    # (some Python builds permit it) or the cipher is weak.
    findings, tags = _classify_tls(info.get("protocol", ""), info.get("cipher", ""))
    if findings:
        info["findings"] = findings
    if tags:
        info["severity_tags"] = sorted(set(tags))
    return info


def _parse_http_response(raw: bytes) -> dict:
    """Extract status, headers, and a small body slice from raw HTTP response bytes."""
    info: dict = {}
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines:
            return {"raw": raw[:200].decode("utf-8", errors="replace")}

        # Status line: "HTTP/1.1 200 OK"
        status_line = lines[0].decode("iso-8859-1", errors="replace").strip()
        info["status_line"] = status_line[:120]

        # Headers we care about for fingerprinting.
        interesting = {
            "server", "x-powered-by", "x-application-context",
            "x-kubernetes-pf-flowschema-uid", "www-authenticate",
            "location", "content-type", "x-jenkins", "x-prometheus-api-version",
        }
        headers: dict[str, str] = {}
        for line in lines[1:]:
            try:
                k, _, v = line.decode("iso-8859-1", errors="replace").partition(":")
            except Exception:
                continue
            k_low = k.strip().lower()
            if k_low in interesting:
                headers[k_low] = v.strip()[:200]
        if headers:
            info["headers"] = headers

        # Try to pull <title> if HTML.
        ct = headers.get("content-type", "").lower()
        if "html" in ct or b"<html" in body[:200].lower() or b"<title" in body[:1000].lower():
            try:
                text = body[:4096].decode("utf-8", errors="replace")
                lo = text.lower()
                ti = lo.find("<title")
                if ti != -1:
                    gt = text.find(">", ti)
                    end = lo.find("</title>", gt + 1)
                    if gt != -1 and end != -1:
                        info["title"] = text[gt + 1:end].strip()[:120]
            except Exception:
                pass

        # Small body preview — useful for JSON APIs (Prometheus, k8s, etc.).
        if body:
            preview = body[:200].decode("utf-8", errors="replace").strip()
            # collapse whitespace
            preview = " ".join(preview.split())
            if preview:
                info["body_preview"] = preview[:200]
    except Exception as e:
        info["parse_error"] = str(e)
    return info


def http_get_plain(ip: str, port: int, hostname: str, timeout: float,
                   user_agent: str = DEFAULT_USER_AGENT) -> dict | None:
    """Send an HTTP/1.1 GET / over a plain TCP socket and parse the response."""
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {hostname or ip}:{port}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii", errors="ignore")

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            chunks: list[bytes] = []
            total = 0
            # Read up to 8 KB or until close; whichever comes first.
            while total < 8192:
                try:
                    buf = sock.recv(4096)
                except socket.timeout:
                    break
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
            raw = b"".join(chunks)
            if not raw:
                return None
            if not raw.startswith(b"HTTP/"):
                # Not HTTP — return a short preview so the user can see what it was.
                return {"non_http_response": raw[:120].decode("utf-8", errors="replace").strip()}
            return _parse_http_response(raw)
    except (socket.timeout, OSError) as e:
        return {"error": str(e)}


def http_get_tls(ip: str, port: int, hostname: str, timeout: float,
                 user_agent: str = DEFAULT_USER_AGENT) -> dict | None:
    """Send HTTP GET over a TLS-wrapped socket. Used after a successful TLS handshake."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {hostname or ip}:{port}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii", errors="ignore")

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname or None) as tls:
                tls.settimeout(timeout)
                tls.sendall(request)
                chunks: list[bytes] = []
                total = 0
                while total < 8192:
                    try:
                        buf = tls.recv(4096)
                    except socket.timeout:
                        break
                    if not buf:
                        break
                    chunks.append(buf)
                    total += len(buf)
                raw = b"".join(chunks)
                if not raw:
                    return None
                if not raw.startswith(b"HTTP/"):
                    return {"non_http_response": raw[:120].decode("utf-8", errors="replace").strip()}
                return _parse_http_response(raw)
    except (socket.timeout, ssl.SSLError, OSError) as e:
        return {"error": str(e)}


def scan_port(ip: str, port: int, hostname: str, timeout: float,
              grab_banners: bool, probe_http: bool = True,
              user_agent: str = DEFAULT_USER_AGENT) -> PortResult:
    result = PortResult(port=port, state="closed", service=service_name(port))

    # Ports where the protocol is well-known not to be HTTP — skip the HTTP probe
    # to save time and avoid weird side effects on protocol state machines.
    non_http_ports = {
        21, 22, 23, 25, 53, 110, 111, 135, 137, 138, 139, 143, 161, 162,
        389, 445, 465, 514, 587, 636, 993, 995, 1433, 1434, 1521,
        2049, 3306, 3389, 5432, 5900, 6379, 9042, 11211, 27017, 27018, 27019,
        2181, 5672, 4369, 25672, 9092, 4222, 6222, 1883, 8883,
        # Cluster / mesh data planes that aren't HTTP at the root path:
        179, 4789, 8285, 8472,
    }
    should_probe_http = grab_banners and probe_http and port not in non_http_ports

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            rc = sock.connect_ex((ip, port))

            if rc != 0:
                result.state = "closed"
                return result

            result.state = "open"

            if not grab_banners:
                return result

            # TLS ports: TLS handshake first (cert info + version/cipher analysis),
            # then HTTPS GET — but only if the server speaks modern TLS. Forcing
            # the HTTP probe over a deprecated-TLS handshake would require widening
            # the SSL context again; not worth the added complexity since the
            # weakness is already captured in tls_info.
            if port in TLS_PORTS:
                result.tls_info = grab_tls_info(ip, port, hostname, timeout)
                if probe_http and result.tls_info:
                    has_error = "error" in result.tls_info
                    is_legacy = "DEPRECATED_TLS" in result.tls_info.get("severity_tags", [])
                    if not has_error and not is_legacy:
                        result.http_info = http_get_tls(ip, port, hostname, timeout, user_agent)
                    elif is_legacy:
                        result.http_info = {
                            "error": "HTTPS probe skipped — server uses deprecated TLS "
                                     "(see tls_info.severity_tags)"
                        }
                return result

            # Plain protocol-specific banner grab on the already-open socket.
            probe = BANNER_PROBES.get(port)
            try:
                if probe is not None:
                    payload = probe % hostname.encode() if b"%s" in probe else probe
                    if payload:
                        sock.sendall(payload)
                sock.settimeout(min(timeout, 2.0))
                data = sock.recv(2048)
                if data:
                    result.banner = data.decode("utf-8", errors="replace").strip()[:400]
            except socket.timeout:
                pass
            except OSError as e:
                result.banner = f"(banner read error: {e})"

    except socket.timeout:
        result.state = "filtered"
        return result
    except OSError as e:
        result.state = "error"
        result.error = str(e)
        return result

    # Separate plain HTTP probe (fresh connection) for non-TLS open ports.
    # We do this after the banner attempt so the protocol-specific probe gets
    # a clean shot first. If port 80 already returned an HTTP banner, this
    # call effectively re-confirms it with structured parsing.
    if should_probe_http and result.state == "open":
        result.http_info = http_get_plain(ip, port, hostname, timeout, user_agent)

    return result


def scan_host(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    grab_banners: bool,
    probe_http: bool = True,
    user_agent: str = DEFAULT_USER_AGENT,
) -> HostResult:
    host = HostResult(target=target)
    host.scan_started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    ip, rdns, err = resolve(target)
    host.resolved_ip = ip
    host.reverse_dns = rdns
    host.resolution_error = err

    if err:
        host.scan_finished = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        return host

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, ip, port, target, timeout, grab_banners, probe_http, user_agent): port
            for port in ports
        }
        for fut in concurrent.futures.as_completed(futures):
            host.ports.append(fut.result())

    host.ports.sort(key=lambda p: p.port)
    host.scan_finished = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return host


# -------- Reporting --------

def fmt_text_report(hosts: list[HostResult], show_closed: bool) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("PORT SCAN REPORT")
    lines.append(f"Generated: {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"Hosts scanned: {len(hosts)}")
    lines.append("=" * 78)

    # --- Collect TLS findings across all hosts for an up-front summary ---
    tls_issues: list[tuple[str, int, list[str]]] = []  # (target, port, findings)
    for h in hosts:
        for p in h.ports:
            if p.tls_info and p.tls_info.get("findings"):
                tls_issues.append((h.target, p.port, p.tls_info["findings"]))

    if tls_issues:
        lines.append("")
        lines.append("TLS / CIPHER FINDINGS  (deprecated TLS < 1.2 or weak ciphers)")
        lines.append("-" * 78)
        for target, port, findings in tls_issues:
            for f in findings:
                lines.append(f"  {target}:{port}  →  {f}")
        lines.append("-" * 78)

    for h in hosts:
        lines.append("")
        lines.append(f"Target: {h.target}")
        if h.resolution_error:
            lines.append(f"  ERROR: {h.resolution_error}")
            continue
        lines.append(f"  Resolved IP : {h.resolved_ip}")
        if h.reverse_dns:
            lines.append(f"  Reverse DNS : {h.reverse_dns}")
        lines.append(f"  Scanned     : {len(h.ports)} ports  ({h.scan_started} → {h.scan_finished})")
        lines.append(f"  Open ports  : {len(h.open_ports())}")
        lines.append("")

        if not h.ports:
            continue

        lines.append(f"  {'PORT':<8}{'STATE':<10}{'SERVICE':<14}DETAIL")
        lines.append(f"  {'-'*8}{'-'*10}{'-'*14}{'-'*40}")

        for p in h.ports:
            if not show_closed and p.state != "open":
                continue

            # Build primary detail (the same line as PORT/STATE/SERVICE).
            detail = ""
            tls_findings: list[str] = []
            if p.banner:
                detail = p.banner.replace("\n", " ").replace("\r", "")[:80]
            elif p.tls_info:
                ti = p.tls_info
                if "error" in ti and "protocol" not in ti:
                    detail = f"TLS error: {ti['error']}"
                else:
                    tags = ti.get("severity_tags", [])
                    marker = ""
                    if "DEPRECATED_TLS" in tags:
                        marker = "[!!] "
                    elif "WEAK_CIPHER" in tags:
                        marker = "[!]  "
                    detail = f"{marker}{ti.get('protocol','?')} | {ti.get('subject','')[:55]}"
                    tls_findings = ti.get("findings", [])
            elif p.error:
                detail = p.error
            lines.append(f"  {p.port:<8}{p.state:<10}{p.service:<14}{detail}")

            # TLS findings on continuation lines, prominently flagged.
            if tls_findings:
                indent = " " * 32
                for finding in tls_findings:
                    lines.append(f"{indent}>>> TLS FINDING: {finding}")
                # Also show the cipher when there's a finding — context matters.
                cipher = p.tls_info.get("cipher", "") if p.tls_info else ""
                if cipher:
                    lines.append(f"{indent}    Cipher: {cipher}")

            # HTTP info (printed on indented continuation lines when present).
            if p.http_info:
                hi = p.http_info
                indent = " " * 32
                if "error" in hi:
                    lines.append(f"{indent}HTTP: (no response — {hi['error']})")
                elif "non_http_response" in hi:
                    lines.append(f"{indent}HTTP: (non-HTTP reply: {hi['non_http_response'][:60]})")
                else:
                    status = hi.get("status_line", "")
                    if status:
                        lines.append(f"{indent}HTTP: {status}")
                    headers = hi.get("headers", {})
                    server = headers.get("server")
                    if server:
                        lines.append(f"{indent}      Server: {server}")
                    powered = headers.get("x-powered-by")
                    if powered:
                        lines.append(f"{indent}      X-Powered-By: {powered}")
                    loc = headers.get("location")
                    if loc:
                        lines.append(f"{indent}      Location: {loc}")
                    auth = headers.get("www-authenticate")
                    if auth:
                        lines.append(f"{indent}      WWW-Authenticate: {auth[:80]}")
                    ct = headers.get("content-type")
                    if ct:
                        lines.append(f"{indent}      Content-Type: {ct}")
                    title = hi.get("title")
                    if title:
                        lines.append(f"{indent}      Title: {title}")
                    preview = hi.get("body_preview")
                    if preview and not title:
                        lines.append(f"{indent}      Body: {preview[:100]}")

    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


def to_json(hosts: list[HostResult]) -> str:
    def conv(h: HostResult) -> dict:
        d = dataclasses.asdict(h)
        return d
    return json.dumps([conv(h) for h in hosts], indent=2)


# -------- HTML reporting --------

_HTML_CSS = """
:root {
  --bg: #0f1419;
  --bg-elev: #161b22;
  --bg-card: #1c2128;
  --border: #30363d;
  --text: #e6edf3;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --ok: #3fb950;
  --warn: #d29922;
  --crit: #f85149;
  --code-bg: #0d1117;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --bg-elev: #f6f8fa;
    --bg-card: #ffffff;
    --border: #d0d7de;
    --text: #1f2328;
    --text-dim: #59636e;
    --accent: #0969da;
    --ok: #1a7f37;
    --warn: #9a6700;
    --crit: #cf222e;
    --code-bg: #f6f8fa;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.container { max-width: 1200px; margin: 0 auto; }
h1 { margin: 0 0 4px; font-size: 24px; font-weight: 600; }
h2 { margin: 32px 0 12px; font-size: 18px; font-weight: 600; }
h3 { margin: 0; font-size: 15px; font-weight: 600; }
.subtitle { color: var(--text-dim); margin-bottom: 24px; font-size: 13px; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
  padding: 16px;
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 8px;
}
.meta-grid .label { color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
.meta-grid .value { font-size: 18px; font-weight: 600; margin-top: 2px; }
.meta-grid .value.crit { color: var(--crit); }
.meta-grid .value.warn { color: var(--warn); }
.meta-grid .value.ok { color: var(--ok); }

.findings-panel {
  background: var(--bg-card);
  border: 1px solid var(--crit);
  border-left: 4px solid var(--crit);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 24px;
}
.findings-panel h2 { margin-top: 0; color: var(--crit); }
.findings-panel ul { margin: 0; padding-left: 20px; }
.findings-panel li { margin: 4px 0; }
.findings-panel .ref { color: var(--accent); font-family: var(--mono); font-size: 12px; }

details.host {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
  overflow: hidden;
}
details.host[open] { background: var(--bg-card); }
details.host summary {
  padding: 14px 18px;
  cursor: pointer;
  user-select: none;
  display: flex;
  align-items: center;
  gap: 12px;
  list-style: none;
}
details.host summary::-webkit-details-marker { display: none; }
details.host summary::before {
  content: "▸";
  color: var(--text-dim);
  transition: transform 0.15s;
  display: inline-block;
  width: 12px;
}
details.host[open] summary::before { transform: rotate(90deg); }
.host-summary-target { font-weight: 600; font-family: var(--mono); }
.host-summary-meta { color: var(--text-dim); font-size: 13px; margin-left: auto; }
.host-summary-meta .pill { margin-left: 8px; }

.pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  font-family: var(--mono);
}
.pill.ok    { background: rgba(63, 185, 80, 0.15);  color: var(--ok); }
.pill.warn  { background: rgba(210, 153, 34, 0.15); color: var(--warn); }
.pill.crit  { background: rgba(248, 81, 73, 0.15);  color: var(--crit); }
.pill.neutral { background: rgba(139, 148, 158, 0.15); color: var(--text-dim); }

.host-body { padding: 0 18px 18px; }
.host-meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 8px 24px;
  padding: 12px 0;
  border-top: 1px solid var(--border);
  font-size: 13px;
}
.host-meta .k { color: var(--text-dim); margin-right: 6px; }
.host-meta .v { font-family: var(--mono); }

table.ports {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  font-size: 13px;
}
table.ports th {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  color: var(--text-dim);
  font-weight: 600;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
table.ports td {
  padding: 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
table.ports tr:last-child td { border-bottom: none; }
table.ports tr.row-crit { background: rgba(248, 81, 73, 0.05); }
table.ports tr.row-warn { background: rgba(210, 153, 34, 0.05); }
.port-num { font-family: var(--mono); font-weight: 600; }
.svc { color: var(--text-dim); font-family: var(--mono); }

.detail-block {
  margin-top: 6px;
  padding: 8px 10px;
  background: var(--code-bg);
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.5;
  word-break: break-word;
}
.detail-block .k { color: var(--text-dim); }
.detail-block .v { color: var(--text); }
.detail-block .finding { color: var(--crit); font-weight: 600; }
.detail-block .warn-text { color: var(--warn); }
.detail-block + .detail-block { margin-top: 4px; }
.banner { font-family: var(--mono); font-size: 12px; color: var(--text-dim); word-break: break-all; }

.no-findings {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-left: 4px solid var(--ok);
  border-radius: 8px;
  padding: 12px 16px;
  margin-bottom: 24px;
  color: var(--text-dim);
  font-size: 13px;
}
.no-findings strong { color: var(--ok); }

footer {
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 12px;
}
footer code { font-family: var(--mono); background: var(--code-bg); padding: 1px 5px; border-radius: 3px; }
"""


def _esc(s: object) -> str:
    """HTML-escape; coerce None and other types safely."""
    if s is None:
        return ""
    return html.escape(str(s), quote=True)


def _port_severity(p: PortResult) -> str:
    """Return 'crit', 'warn', or '' for row styling."""
    if p.tls_info:
        tags = p.tls_info.get("severity_tags", []) or []
        if "DEPRECATED_TLS" in tags:
            return "crit"
        if "WEAK_CIPHER" in tags:
            return "warn"
    return ""


def _render_tls_block(ti: dict) -> str:
    """Render the TLS section of a port row as HTML."""
    if not ti:
        return ""
    parts: list[str] = ['<div class="detail-block">']

    if "error" in ti and "protocol" not in ti:
        parts.append(f'<span class="finding">TLS handshake failed:</span> {_esc(ti["error"])}')
        if ti.get("legacy_error"):
            parts.append(f'<br><span class="k">Legacy retry also failed:</span> {_esc(ti["legacy_error"])}')
        parts.append("</div>")
        return "".join(parts)

    proto = ti.get("protocol", "?")
    tags = ti.get("severity_tags", []) or []
    proto_class = "finding" if "DEPRECATED_TLS" in tags else (
        "warn-text" if "WEAK_CIPHER" in tags else "v"
    )
    parts.append(f'<span class="k">Protocol:</span> <span class="{proto_class}">{_esc(proto)}</span>')
    if ti.get("cipher"):
        cipher_class = "warn-text" if "WEAK_CIPHER" in tags else "v"
        parts.append(f' &nbsp; <span class="k">Cipher:</span> <span class="{cipher_class}">{_esc(ti["cipher"])}</span>')

    for finding in ti.get("findings", []) or []:
        parts.append(f'<br><span class="finding">⚠ {_esc(finding)}</span>')

    if ti.get("modern_handshake_error"):
        parts.append(f'<br><span class="k">Modern handshake error:</span> {_esc(ti["modern_handshake_error"])}')

    if ti.get("subject"):
        parts.append(f'<br><span class="k">Subject:</span> {_esc(ti["subject"])}')
    if ti.get("issuer"):
        parts.append(f'<br><span class="k">Issuer:</span> {_esc(ti["issuer"])}')
    if ti.get("not_before") or ti.get("not_after"):
        parts.append(
            f'<br><span class="k">Validity:</span> '
            f'{_esc(ti.get("not_before",""))} → {_esc(ti.get("not_after",""))}'
        )
    san = ti.get("san") or []
    if san:
        # Truncate very long SAN lists
        shown = san[:8]
        more = f" (+{len(san) - 8} more)" if len(san) > 8 else ""
        parts.append(f'<br><span class="k">SAN:</span> {_esc(", ".join(shown))}{_esc(more)}')

    parts.append("</div>")
    return "".join(parts)


def _render_http_block(hi: dict) -> str:
    """Render the HTTP section of a port row as HTML."""
    if not hi:
        return ""
    parts: list[str] = ['<div class="detail-block">']

    if "error" in hi:
        parts.append(f'<span class="k">HTTP:</span> <span class="warn-text">{_esc(hi["error"])}</span>')
        parts.append("</div>")
        return "".join(parts)

    if "non_http_response" in hi:
        parts.append(
            f'<span class="k">HTTP probe got non-HTTP reply:</span> '
            f'<span class="v">{_esc(hi["non_http_response"])}</span>'
        )
        parts.append("</div>")
        return "".join(parts)

    status = hi.get("status_line", "")
    if status:
        parts.append(f'<span class="k">HTTP:</span> <span class="v">{_esc(status)}</span>')

    headers = hi.get("headers", {}) or {}
    interesting_order = ["server", "x-powered-by", "x-jenkins", "x-prometheus-api-version",
                         "location", "www-authenticate", "content-type"]
    header_labels = {
        "server": "Server",
        "x-powered-by": "X-Powered-By",
        "x-jenkins": "X-Jenkins",
        "x-prometheus-api-version": "X-Prometheus-Api-Version",
        "location": "Location",
        "www-authenticate": "WWW-Authenticate",
        "content-type": "Content-Type",
    }
    for k in interesting_order:
        v = headers.get(k)
        if v:
            parts.append(f'<br><span class="k">{header_labels[k]}:</span> <span class="v">{_esc(v)}</span>')

    if hi.get("title"):
        parts.append(f'<br><span class="k">Title:</span> <span class="v">{_esc(hi["title"])}</span>')
    elif hi.get("body_preview"):
        parts.append(f'<br><span class="k">Body:</span> <span class="v">{_esc(hi["body_preview"][:160])}</span>')

    parts.append("</div>")
    return "".join(parts)


def _render_port_row(p: PortResult) -> str:
    """Render one <tr> for the ports table."""
    sev = _port_severity(p)
    row_cls = f' class="row-{sev}"' if sev else ""

    state_pill_class = {
        "open": "ok",
        "closed": "neutral",
        "filtered": "warn",
        "error": "crit",
    }.get(p.state, "neutral")

    cells: list[str] = []
    cells.append(f'<td class="port-num">{p.port}</td>')
    cells.append(f'<td><span class="pill {state_pill_class}">{_esc(p.state)}</span></td>')
    cells.append(f'<td class="svc">{_esc(p.service or "—")}</td>')

    # Detail column: banner, TLS block, HTTP block, or error message.
    detail_parts: list[str] = []
    if p.banner:
        detail_parts.append(f'<div class="banner">{_esc(p.banner[:300])}</div>')
    if p.tls_info:
        detail_parts.append(_render_tls_block(p.tls_info))
    if p.http_info:
        detail_parts.append(_render_http_block(p.http_info))
    if p.error and not detail_parts:
        detail_parts.append(f'<div class="banner warn-text">{_esc(p.error)}</div>')
    if not detail_parts:
        detail_parts.append('<span style="color: var(--text-dim);">—</span>')

    cells.append(f'<td>{"".join(detail_parts)}</td>')

    return f'<tr{row_cls}>{"".join(cells)}</tr>'


def fmt_html_report(hosts: list[HostResult], show_closed: bool, metadata: dict | None = None) -> str:
    """Render the full HTML report as a single self-contained document."""
    metadata = metadata or {}
    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    # Aggregate stats across hosts
    total_hosts = len(hosts)
    total_open = sum(len(h.open_ports()) for h in hosts)
    total_scanned_ports = sum(len(h.ports) for h in hosts)
    failed_resolution = sum(1 for h in hosts if h.resolution_error)

    # Collect TLS findings across hosts (target, port, finding strings)
    tls_issues: list[tuple[str, int, list[str]]] = []
    crit_count = 0
    warn_count = 0
    for h in hosts:
        for p in h.ports:
            if p.tls_info and p.tls_info.get("findings"):
                tls_issues.append((h.target, p.port, p.tls_info["findings"]))
                tags = p.tls_info.get("severity_tags", []) or []
                if "DEPRECATED_TLS" in tags:
                    crit_count += 1
                elif "WEAK_CIPHER" in tags:
                    warn_count += 1

    # --- Header block ---
    out: list[str] = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en"><head>')
    out.append('<meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    out.append(f"<title>Port Scan Report — {_esc(generated)}</title>")
    out.append(f"<style>{_HTML_CSS}</style>")
    out.append("</head><body><div class='container'>")

    out.append("<h1>Port Scan Report</h1>")
    subtitle_bits = [f"Generated {_esc(generated)}"]
    if metadata.get("user_agent"):
        subtitle_bits.append(f"UA: <code>{_esc(metadata['user_agent'])}</code>")
    if metadata.get("port_spec"):
        subtitle_bits.append(f"Profile: <code>{_esc(metadata['port_spec'])}</code>")
    out.append(f'<div class="subtitle">{" &nbsp;·&nbsp; ".join(subtitle_bits)}</div>')

    # --- Top metrics grid ---
    out.append('<div class="meta-grid">')
    out.append(f'<div><div class="label">Hosts scanned</div><div class="value">{total_hosts}</div></div>')
    out.append(f'<div><div class="label">Ports per host</div><div class="value">{total_scanned_ports // max(total_hosts,1)}</div></div>')
    out.append(f'<div><div class="label">Open ports (total)</div><div class="value">{total_open}</div></div>')
    crit_class = "crit" if crit_count > 0 else "ok"
    out.append(f'<div><div class="label">Deprecated TLS</div><div class="value {crit_class}">{crit_count}</div></div>')
    warn_class = "warn" if warn_count > 0 else "ok"
    out.append(f'<div><div class="label">Weak ciphers</div><div class="value {warn_class}">{warn_count}</div></div>')
    if failed_resolution:
        out.append(f'<div><div class="label">DNS failures</div><div class="value warn">{failed_resolution}</div></div>')
    out.append("</div>")

    # --- TLS findings panel (or "no findings" reassurance) ---
    if tls_issues:
        out.append('<section class="findings-panel">')
        out.append("<h2>⚠ TLS / Cipher Findings</h2>")
        out.append("<ul>")
        for target, port, findings in tls_issues:
            for f in findings:
                out.append(
                    f'<li><span class="ref">{_esc(target)}:{port}</span> &nbsp; {_esc(f)}</li>'
                )
        out.append("</ul>")
        out.append("</section>")
    else:
        out.append(
            '<div class="no-findings"><strong>✓ No TLS findings.</strong> '
            "No deprecated protocol versions or weak ciphers detected on scanned TLS ports.</div>"
        )

    # --- Per-host sections ---
    out.append("<h2>Hosts</h2>")
    for h in hosts:
        open_count = len(h.open_ports())
        # Auto-expand hosts that have findings or open ports; collapse clean ones.
        has_finding = any(
            (p.tls_info or {}).get("findings") for p in h.ports
        )
        open_attr = " open" if (has_finding or open_count > 0) else ""

        # Build summary line
        pills: list[str] = []
        if h.resolution_error:
            pills.append('<span class="pill crit">DNS failed</span>')
        else:
            pill_class = "ok" if open_count > 0 else "neutral"
            pills.append(f'<span class="pill {pill_class}">{open_count} open</span>')
        if has_finding:
            pills.append('<span class="pill crit">TLS finding</span>')

        out.append(f"<details class='host'{open_attr}>")
        out.append("<summary>")
        out.append(f'<span class="host-summary-target">{_esc(h.target)}</span>')
        if h.resolved_ip and h.resolved_ip != h.target:
            out.append(f' <span style="color: var(--text-dim);">({_esc(h.resolved_ip)})</span>')
        out.append(f'<span class="host-summary-meta">{"".join(pills)}</span>')
        out.append("</summary>")

        out.append("<div class='host-body'>")

        if h.resolution_error:
            out.append(
                f'<div class="host-meta"><div><span class="k">Error:</span> '
                f'<span class="v" style="color: var(--crit);">{_esc(h.resolution_error)}</span></div></div>'
            )
            out.append("</div></details>")
            continue

        # Per-host metadata
        out.append('<div class="host-meta">')
        out.append(f'<div><span class="k">Resolved IP:</span><span class="v"> {_esc(h.resolved_ip)}</span></div>')
        if h.reverse_dns:
            out.append(f'<div><span class="k">Reverse DNS:</span><span class="v"> {_esc(h.reverse_dns)}</span></div>')
        out.append(f'<div><span class="k">Ports scanned:</span><span class="v"> {len(h.ports)}</span></div>')
        out.append(f'<div><span class="k">Open ports:</span><span class="v"> {open_count}</span></div>')
        out.append(f'<div><span class="k">Started:</span><span class="v"> {_esc(h.scan_started)}</span></div>')
        out.append(f'<div><span class="k">Finished:</span><span class="v"> {_esc(h.scan_finished)}</span></div>')
        out.append("</div>")

        # Port table
        visible_ports = [p for p in h.ports if show_closed or p.state == "open"]
        if not visible_ports:
            out.append('<div style="color: var(--text-dim); padding: 12px 0;">No open ports.</div>')
        else:
            out.append("<table class='ports'>")
            out.append("<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Detail</th></tr></thead>")
            out.append("<tbody>")
            for p in visible_ports:
                out.append(_render_port_row(p))
            out.append("</tbody></table>")

        out.append("</div></details>")

    # --- Footer ---
    out.append("<footer>")
    out.append("Generated by <code>portscan.py</code>. Authorized security assessment use only.")
    out.append("</footer>")
    out.append("</div></body></html>")
    return "\n".join(out)



# -------- Target loading --------

def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.targets:
        targets.extend(args.targets)
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            raise SystemExit(f"Targets file not found: {path}")
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    # de-dup, preserve order
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# -------- CLI --------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="TCP port scanner with banner grabbing and TLS inspection."
    )
    p.add_argument("-t", "--targets", nargs="+", help="Hostnames or IPs to scan.")
    p.add_argument("-f", "--file", help="File with one target per line (# for comments).")
    p.add_argument(
        "-p", "--ports", default="common",
        help=(
            "Ports to scan. Profiles: 'common', 'kubernetes' (or 'k8s'), "
            "'observability' (or 'monitoring' / 'obs'), 'all'. "
            "Numeric: '1-1024', '22,80,443'. Combine with '+' or ',' "
            "e.g. 'common+k8s+monitoring' or 'k8s,8080,9000-9010'. "
            "Default: common."
        ),
    )
    p.add_argument("--timeout", type=float, default=1.5, help="Per-connection timeout in seconds.")
    p.add_argument("--workers", type=int, default=100, help="Concurrent connections per host.")
    p.add_argument("--no-banner", action="store_true",
                   help="Skip banner grabbing, TLS info, and HTTP probing entirely (fast connect-scan only).")
    p.add_argument("--no-http", action="store_true",
                   help="Skip the HTTP GET probe on open ports (still does banners + TLS info).")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT, metavar="STRING",
                   help=(
                       "User-Agent header for HTTP probes. The default is distinctive and "
                       "identifies the source host so you can filter your own probes out of "
                       "target access logs. Override to use an engagement-specific tag "
                       f"(e.g. 'PenTest-acme-2026Q2'). Default: {DEFAULT_USER_AGENT!r}"
                   ))
    p.add_argument("--show-closed", action="store_true", help="Include closed/filtered ports in text report.")
    p.add_argument("--json", metavar="PATH", help="Write JSON report to this path.")
    p.add_argument("--text", metavar="PATH", help="Write text report to this path (in addition to stdout).")
    p.add_argument("--html", metavar="PATH",
                   help="Write a self-contained HTML report to this path. "
                        "Suitable for emailing, archiving, or hosting as a static file.")
    p.add_argument("--html", metavar="PATH",
                   help="Write a self-contained HTML report to this path. The file embeds CSS "
                        "and JS, has no external dependencies, and is safe to email or upload.")
    p.add_argument("--confirm", action="store_true",
                   help="Confirm you have authorization to scan these targets.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    targets = load_targets(args)
    if not targets:
        print("No targets provided. Use -t or -f.", file=sys.stderr)
        return 2

    if not args.confirm:
        print("WARNING: Port scanning systems you do not own or have written")
        print("permission to test may be illegal. Re-run with --confirm to proceed.")
        print(f"Targets queued: {', '.join(targets)}")
        return 1

    try:
        ports = parse_port_spec(args.ports)
    except ValueError as e:
        print(f"Invalid --ports value: {e}", file=sys.stderr)
        return 2

    print(f"Scanning {len(targets)} target(s) across {len(ports)} port(s)...", file=sys.stderr)
    if not args.no_banner and not args.no_http:
        print(f"HTTP probe User-Agent: {args.user_agent}", file=sys.stderr)

    results: list[HostResult] = []
    for tgt in targets:
        print(f"  → {tgt}", file=sys.stderr)
        results.append(scan_host(
            target=tgt,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=not args.no_banner,
            probe_http=not args.no_http,
            user_agent=args.user_agent,
        ))

    text_report = fmt_text_report(results, show_closed=args.show_closed)
    print(text_report)

    if args.text:
        Path(args.text).write_text(text_report)
        print(f"Text report written to {args.text}", file=sys.stderr)

    if args.json:
        Path(args.json).write_text(to_json(results))
        print(f"JSON report written to {args.json}", file=sys.stderr)

    if args.html:
        html_report = fmt_html_report(
            results,
            show_closed=args.show_closed,
            metadata={
                "port_count": len(ports),
                "port_spec": args.ports,
                "user_agent": args.user_agent if not args.no_banner and not args.no_http else None,
            },
        )
        Path(args.html).write_text(html_report, encoding="utf-8")
        print(f"HTML report written to {args.html}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
