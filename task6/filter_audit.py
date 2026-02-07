#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter_audit.py — фильтрация Kubernetes audit.log (NDJSON) под инциденты из задания.

Извлекает подозрительные события:
- secrets access (get/list/watch), включая forbidden (403) и impersonation
- pod exec (subresource exec) — ловит и streaming варианты (verb не только create; иногда get/connect)
- privileged pods + hostPath/hostNetwork/hostPID/hostIPC/allowPrivilegeEscalation
- RoleBinding/ClusterRoleBinding на cluster-admin (если requestObject доступен)
- tampering с audit policy (audit-policy / audit.log / ConfigMap audit-policy)

Выход:
- audit-extract.json (NDJSON) — строки исходных audit events, признанные подозрительными
- stdout — краткая статистика по категориям

Примеры:
  python filter_audit.py --input audit.log --output audit-extract.json
  python filter_audit.py --input audit.log --output audit-extract.json --since "2026-02-07T12:00:00Z" --until "2026-02-07T12:30:00Z"
  python filter_audit.py --input audit.log --output audit-extract.json --include-system
"""
import argparse
import json
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

STAGE_PRIORITY = {"ResponseComplete": 3, "ResponseStarted": 2, "RequestReceived": 1}
JSON_RE = re.compile(r"(\{.*\})")

def parse_rfc3339(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None

def iter_events(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                m = JSON_RE.search(line)
                if not m:
                    continue
                line = m.group(1)
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if isinstance(ev, dict) and str(ev.get("apiVersion", "")).startswith("audit.k8s.io/"):
                yield ev

def objref(ev: Dict[str, Any]) -> Dict[str, Any]:
    return ev.get("objectRef") or {}

def user(ev: Dict[str, Any]) -> Dict[str, Any]:
    return ev.get("user") or {}

def imp_user(ev: Dict[str, Any]) -> Dict[str, Any]:
    return ev.get("impersonatedUser") or {}

def resp(ev: Dict[str, Any]) -> Dict[str, Any]:
    return ev.get("responseStatus") or {}

def uri(ev: Dict[str, Any]) -> str:
    return ev.get("requestURI") or ""

def stage(ev: Dict[str, Any]) -> str:
    return ev.get("stage") or ""

def ts(ev: Dict[str, Any]) -> str:
    return ev.get("requestReceivedTimestamp") or ev.get("stageTimestamp") or ""

def is_system_actor(username: str) -> bool:
    return username.startswith("system:")

def is_secrets_event(ev: Dict[str, Any]) -> bool:
    o = objref(ev)
    if o.get("resource") == "secrets" and ev.get("verb") in ("get", "list", "watch"):
        return True
    return "/secrets" in uri(ev)

def is_exec_event(ev: Dict[str, Any]) -> bool:
    o = objref(ev)
    if o.get("resource") == "pods" and o.get("subresource") == "exec":
        return True
    u = uri(ev)
    return ("/pods/" in u and "/exec" in u)

def is_rolebinding_cluster_admin(ev: Dict[str, Any]) -> bool:
    o = objref(ev)
    if o.get("resource") not in ("rolebindings", "clusterrolebindings"):
        return False
    if ev.get("verb") not in ("create", "update", "patch"):
        return False
    ro = ev.get("requestObject") or {}
    if not isinstance(ro, dict):
        return False
    role_ref = ro.get("roleRef") or {}
    return isinstance(role_ref, dict) and role_ref.get("name") == "cluster-admin"

def pod_spec(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ro = ev.get("requestObject")
    if not isinstance(ro, dict):
        return None
    spec = ro.get("spec")
    return spec if isinstance(spec, dict) else None

def pod_risk_reasons(ev: Dict[str, Any]) -> List[str]:
    o = objref(ev)
    if o.get("resource") != "pods" or ev.get("verb") != "create":
        return []
    spec = pod_spec(ev)
    if not spec:
        return []
    reasons: List[str] = []
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(flag) is True:
            reasons.append(flag)
    vols = spec.get("volumes")
    if isinstance(vols, list):
        for v in vols:
            if isinstance(v, dict) and "hostPath" in v:
                reasons.append("hostPath")
    containers: List[Dict[str, Any]] = []
    for k in ("containers", "initContainers", "ephemeralContainers"):
        cs = spec.get(k)
        if isinstance(cs, list):
            containers.extend([c for c in cs if isinstance(c, dict)])
    for c in containers:
        sc = c.get("securityContext")
        if isinstance(sc, dict):
            if sc.get("privileged") is True:
                reasons.append("privileged")
            if sc.get("allowPrivilegeEscalation") is True:
                reasons.append("allowPrivilegeEscalation")
    return sorted(set(reasons))

def is_audit_policy_tamper(ev: Dict[str, Any]) -> bool:
    o = objref(ev)
    nm = (o.get("name") or "")
    u = uri(ev)
    if "audit-policy" in u or "audit-policy" in nm:
        return True
    if "audit.log" in u or "audit.log" in nm:
        return True
    if o.get("resource") == "configmaps" and nm == "audit-policy" and ev.get("verb") in ("delete", "update", "patch"):
        return True
    return False

def classify(ev: Dict[str, Any], include_system: bool) -> List[str]:
    tags: List[str] = []
    o = objref(ev)
    u = user(ev).get("username", "")
    imp = imp_user(ev).get("username", "")
    code = resp(ev).get("code")

    # secrets
    if is_secrets_event(ev) and ev.get("verb") in ("get", "list"):
        if imp:
            tags.append("secrets_access_impersonated")
            if code in (401, 403):
                tags.append("secrets_access_forbidden")
            elif code == 200:
                tags.append("secrets_access_success")
            else:
                tags.append("secrets_access")
        else:
            if include_system or not is_system_actor(u):
                if code == 200:
                    tags.append("secrets_access_success")
                elif code in (401, 403):
                    tags.append("secrets_access_forbidden")
                else:
                    tags.append("secrets_access")

    # exec
    if is_exec_event(ev) and (include_system or not is_system_actor(u)):
        ns = o.get("namespace") or ""
        tags.append("pod_exec_kube_system" if ns == "kube-system" else "pod_exec")

    # risky pods
    reasons = pod_risk_reasons(ev)
    if reasons and (include_system or not is_system_actor(u)):
        tags.append("risky_pod")
        for r in reasons:
            tags.append(f"pod_risk:{r}")

    # cluster-admin binding
    if is_rolebinding_cluster_admin(ev):
        tags.append("cluster_admin_binding")

    # audit policy tamper
    if is_audit_policy_tamper(ev):
        tags.append("audit_policy_tamper")

    return sorted(set(tags))

def dedup_best_stage(events: List[Tuple[Dict[str, Any], List[str]]]) -> List[Tuple[Dict[str, Any], List[str]]]:
    best: Dict[str, Tuple[int, Dict[str, Any], List[str]]] = {}
    for ev, tags in events:
        aid = ev.get("auditID") or ""
        pr = STAGE_PRIORITY.get(stage(ev), 0)
        cur = best.get(aid)
        if cur is None or pr > cur[0]:
            best[aid] = (pr, ev, tags)
    return [(v[1], v[2]) for v in best.values()]

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="path to audit.log (NDJSON)")
    ap.add_argument("--output", required=True, help="path to audit-extract.json (NDJSON)")
    ap.add_argument("--since", default="", help="RFC3339 lower bound, e.g. 2026-02-07T12:00:00Z")
    ap.add_argument("--until", default="", help="RFC3339 upper bound, e.g. 2026-02-07T12:30:00Z")
    ap.add_argument("--include-system", action="store_true", help="include system:* actors in output")
    args = ap.parse_args()

    since_dt = parse_rfc3339(args.since) if args.since else None
    until_dt = parse_rfc3339(args.until) if args.until else None

    selected: List[Tuple[Dict[str, Any], List[str]]] = []
    counts = Counter()
    total = 0
    skipped_time = 0

    for ev in iter_events(args.input):
        total += 1
        t = parse_rfc3339(ts(ev))
        if t:
            if since_dt and t < since_dt:
                skipped_time += 1
                continue
            if until_dt and t > until_dt:
                skipped_time += 1
                continue

        tags = classify(ev, include_system=args.include_system)
        if not tags:
            continue

        for tag in tags:
            counts[tag] += 1
        selected.append((ev, tags))

    best = dedup_best_stage(selected)
    best.sort(key=lambda x: ts(x[0]) or "")

    with open(args.output, "w", encoding="utf-8") as f:
        for ev, _tags in best:
            f.write(json.dumps(ev, ensure_ascii=False) + "\\n")

    print("Total audit events read:", total)
    if since_dt or until_dt:
        print("Skipped by time filter:", skipped_time)
    print("Suspicious events extracted:", len(best))
    print("Top categories:")
    for k, v in counts.most_common(20):
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
