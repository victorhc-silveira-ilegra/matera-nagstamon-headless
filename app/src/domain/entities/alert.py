from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from domain.entities.errors import DomainValidationError
from domain.entities.severity import Severity

RE_EC2 = re.compile(r"^(.+?)-i-[0-9a-f]{8,17}$", re.IGNORECASE)
RE_K8S_DEPLOY = re.compile(r"^(.+?)-[0-9a-f]{8,10}-[a-z0-9]{5}$", re.IGNORECASE)
RE_K8S_HASH_5 = re.compile(
    r"^(.+?)-(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{5}$", re.IGNORECASE
)
RE_K8S_STATEFUL = re.compile(r"^(.+?)-\d+$", re.IGNORECASE)
RE_ENV_PREFIX = re.compile(r"^(?:hml|prd|prod|qa|dev|uat|stg)[-_]", re.IGNORECASE)
RE_VARIANT_SUFFIX = re.compile(r"[-_](?:spb|mp|si|bms|mb)$", re.IGNORECASE)
RE_K8S_SERVER = re.compile(r"(?i)alertmanager")
RE_K8S_TERMS = re.compile(r"(?i)(?:kube|k8s|pod|deployment|daemonset|statefulset)")
RE_WORKLOAD_IN_TEXT = re.compile(
    r"(?i)(?:deployment|pod|container|job|daemonset|statefulset)[:\s/]*([a-z0-9][a-z0-9_-]+)"
)


def canonicalize_target(raw: str) -> str:
    cleaned = raw.strip()
    if not cleaned:
        return ""
    ec2_match = RE_EC2.match(cleaned)
    if ec2_match:
        return ec2_match.group(1)
    deploy_match = RE_K8S_DEPLOY.match(cleaned)
    if deploy_match:
        return deploy_match.group(1)
    hash_match = RE_K8S_HASH_5.match(cleaned)
    if hash_match:
        return hash_match.group(1)
    stateful_match = RE_K8S_STATEFUL.match(cleaned)
    if stateful_match:
        return stateful_match.group(1)
    return cleaned


def normalize_service_base(raw: str) -> str:
    cleaned = canonicalize_target(raw)
    if not cleaned:
        return ""
    cleaned = RE_ENV_PREFIX.sub("", cleaned)
    cleaned = RE_VARIANT_SUFFIX.sub("", cleaned)
    return cleaned.strip()


@dataclass(frozen=True, slots=True)
class Alert:
    server: str
    severity: Severity
    alertname: str
    app: str
    desc: str
    status_text: str = ""
    duration_str: str = ""
    starts_at: datetime | None = None
    alert_state: str = ""
    silenced_by: tuple[str, ...] = ()
    inhibited_by: tuple[str, ...] = ()
    acknowledged: bool = False
    host: str = ""
    environment: str = ""
    notifications_enabled: bool = True
    in_maintenance: bool = False
    is_soft_state: bool = False
    checks_enabled: bool = True

    def __post_init__(self) -> None:
        server = self.server.strip()
        alertname = self.alertname.strip()
        app = self.app.strip()
        if not server:
            raise DomainValidationError("alert server must not be empty")
        if not alertname:
            raise DomainValidationError("alertname must not be empty")
        if not app:
            raise DomainValidationError("alert app must not be empty")
        object.__setattr__(self, "server", server)
        object.__setattr__(self, "alertname", alertname)
        object.__setattr__(self, "app", app)
        object.__setattr__(self, "desc", self.desc.strip())
        object.__setattr__(self, "status_text", self.status_text.strip())
        object.__setattr__(self, "duration_str", self.duration_str.strip())
        object.__setattr__(self, "alert_state", self.alert_state.strip().lower())
        object.__setattr__(self, "host", self.host.strip())
        object.__setattr__(self, "environment", self.environment.strip().upper())

    def is_kubernetes(self) -> bool:
        if RE_K8S_SERVER.search(self.server):
            return True
        return bool(RE_K8S_TERMS.search(f"{self.alertname} {self.host} {self.app}"))

    def canonical_workload(self) -> str:
        if self.is_kubernetes():
            full_text = f"{self.desc} {self.status_text}"
            match = RE_WORKLOAD_IN_TEXT.search(full_text)
            if match and (
                "kube-state-metrics" in self.host.lower()
                or not self.host
                or self.host == self.server
            ):
                return canonicalize_target(match.group(1))
            host_canon = canonicalize_target(self.host)
            if host_canon and "kube-state-metrics" not in host_canon.lower():
                return host_canon
            app_canon = canonicalize_target(self.app)
            if app_canon and "kube-state-metrics" not in app_canon.lower():
                return app_canon
            return host_canon or app_canon
        return normalize_service_base(self.host or self.app)

    def incident_key(self) -> str:
        if self.is_kubernetes():
            workload = self.canonical_workload() or "workload"
            return f"{self.server}\0k8s\0{workload}"
        app = normalize_service_base(self.app)
        host = normalize_service_base(self.host)
        return f"{self.server}\0{self.alertname}\0{app}\0{host}"

    def dedup_key(self) -> str:
        return self.incident_key()
