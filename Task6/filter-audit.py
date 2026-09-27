#!/usr/bin/env python3
"""Выбирает из audit.log Kubernetes подозрительные события.

Правила:
  secrets        - чтение секретов не компонентами control plane;
  privileged-pod - создание или изменение пода с privileged, hostPID, hostIPC,
                   hostNetwork или hostPath;
  exec           - exec, attach и port-forward в под, при любом глаголе:
                   kubectl через WebSocket выполняет exec запросом GET;
  rbac           - привязки ролей cluster-admin, admin, edit и изменения RBAC
                   в kube-system;
  impersonation  - запросы к ресурсам от имени другого пользователя (--as);
  audit          - изменение или удаление объектов, связанных с аудитом;
  denied         - отказ в доступе (403) по любому из правил выше.

События остаются в формате audit.log, к каждому добавляется поле suspicion
со списком сработавших правил. Из объектов убираются managedFields,
значения секретов заменяются на ***.

Использование:
  python3 filter-audit.py audit.log -o audit-extract.json [--since 2026-09-27T12:42:13Z]
--since отсекает события раньше указанного времени, например разворачивание кластера.
"""

import argparse
import json
from collections import Counter

CONTROL_PLANE = ("system:kube-", "system:apiserver", "system:node:",
                 "system:serviceaccount:kube-system:")
READ_VERBS = {"get", "list", "watch"}
WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
POWERFUL_ROLES = {"cluster-admin", "admin", "edit"}
REMOTE_SUBRESOURCES = {"exec", "attach", "portforward"}
POD_SPEC_HOST_FLAGS = ("hostPID", "hostIPC", "hostNetwork")


def is_control_plane(username):
    return username.startswith(CONTROL_PLANE)


def pod_spec(obj):
    if not obj:
        return {}
    if obj.get("kind") == "Pod":
        return obj.get("spec", {})
    return obj.get("spec", {}).get("template", {}).get("spec", {})


def privileged_reasons(spec):
    reasons = []
    containers = (spec.get("containers", []) + spec.get("initContainers", [])
                  + spec.get("ephemeralContainers", []))
    for c in containers:
        if (c.get("securityContext") or {}).get("privileged"):
            reasons.append(f"privileged: {c.get('name')}")
    reasons += [flag for flag in POD_SPEC_HOST_FLAGS if spec.get(flag)]
    reasons += [f"hostPath: {v.get('name')}" for v in spec.get("volumes", []) if "hostPath" in v]
    return reasons


def classify(ev):
    ref = ev.get("objectRef") or {}
    resource, sub = ref.get("resource", ""), ref.get("subresource", "")
    verb = ev.get("verb", "")
    user = ev.get("user", {}).get("username", "")
    rules = []

    if is_control_plane(user):
        return rules

    if resource == "secrets" and verb in READ_VERBS:
        rules.append("secrets")

    if resource in ("pods", "deployments", "daemonsets", "statefulsets", "replicasets",
                    "jobs", "cronjobs") and verb in WRITE_VERBS and not sub:
        if privileged_reasons(pod_spec(ev.get("requestObject"))):
            rules.append("privileged-pod")

    if resource == "pods" and sub in REMOTE_SUBRESOURCES:
        rules.append("exec")

    if resource in ("rolebindings", "clusterrolebindings", "roles", "clusterroles") \
            and verb in WRITE_VERBS:
        role = ((ev.get("requestObject") or {}).get("roleRef") or {}).get("name")
        if role in POWERFUL_ROLES or ref.get("namespace") == "kube-system":
            rules.append("rbac")

    if ev.get("impersonatedUser") and ref:
        rules.append("impersonation")

    target = f"{ev.get('requestURI', '')} {ref.get('name', '')}".lower()
    if "audit" in target and verb in WRITE_VERBS:
        rules.append("audit")

    if rules and (ev.get("responseStatus") or {}).get("code") == 403:
        rules.append("denied")
    return rules


def scrub(obj):
    """Убирает managedFields и значения секретов."""
    if isinstance(obj, dict):
        if obj.get("kind") in ("Secret", "SecretList"):
            obj = dict(obj)
            for key in ("data", "stringData"):
                if key in obj:
                    obj[key] = {k: "***" for k in obj[key]}
        return {k: scrub(v) for k, v in obj.items() if k != "managedFields"}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


def main(src, dst, since):
    extract = []
    with open(src, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("stage") != "ResponseComplete":
                continue
            if since and ev.get("stageTimestamp", "") < since:
                continue
            rules = classify(ev)
            if rules:
                ev = scrub(ev)
                ev["suspicion"] = rules
                extract.append(ev)

    extract.sort(key=lambda e: e.get("stageTimestamp", ""))
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(extract, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    counts = Counter(rule for ev in extract for rule in ev["suspicion"])
    print(f"событий в выжимке: {len(extract)}")
    for rule in ("secrets", "privileged-pod", "exec", "rbac", "impersonation", "audit", "denied"):
        print(f"  {rule:15} {counts.get(rule, 0)}")
    print()
    for ev in extract:
        ref = ev.get("objectRef") or {}
        target = "/".join(p for p in (ref.get("namespace"), ref.get("resource"),
                                      ref.get("subresource"), ref.get("name")) if p)
        who = ev["user"]["username"]
        if ev.get("impersonatedUser"):
            who += f" as {ev['impersonatedUser']['username']}"
        print(f"{ev['stageTimestamp']}  {ev['verb']:7} {target:55} "
              f"{ev['responseStatus']['code']}  {who}  [{', '.join(ev['suspicion'])}]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Подозрительные события из audit.log")
    parser.add_argument("audit_log")
    parser.add_argument("-o", "--output", default="audit-extract.json")
    parser.add_argument("--since", help="время начала анализа, RFC 3339 в UTC")
    args = parser.parse_args()
    main(args.audit_log, args.output, args.since)
