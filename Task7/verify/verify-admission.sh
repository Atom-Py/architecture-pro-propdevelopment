#!/usr/bin/env bash
# Проверяет, что admission controllers включены и отклоняют небезопасные поды:
#   1. PodSecurity Admission: уровень restricted на audit-zone и отказ
#      для манифестов из insecure-manifests;
#   2. OPA Gatekeeper: вебхук, шаблоны и ограничения в режиме deny, отказ
#      для тех же манифестов в namespace gatekeeper-check без ограничений
#      PodSecurity. В audit-zone PodSecurity срабатывает раньше вебхука
#      Gatekeeper, поэтому отдельно Gatekeeper проверяется там.
# Поды не создаются, запросы выполняются с --dry-run=server.
# Использование: ./verify/verify-admission.sh
set -uo pipefail

base="$(cd "$(dirname "$0")/.." && pwd)"
failed=0

ok()   { echo "  OK    $*"; }
fail() { echo "  FAIL  $*"; failed=$((failed + 1)); }

echo "PodSecurity Admission"
for mode in enforce audit warn; do
  level="$(kubectl get ns audit-zone -o jsonpath="{.metadata.labels.pod-security\.kubernetes\.io/$mode}")"
  [ "$level" = restricted ] && ok "audit-zone: $mode=$level" || fail "audit-zone: $mode=${level:-нет}"
done
for f in "$base"/insecure-manifests/*.yaml; do
  out="$(kubectl apply --dry-run=server -f "$f" 2>&1)"
  if grep -q 'violates PodSecurity "restricted' <<< "$out"; then
    ok "$(basename "$f") отклонён: $(grep -o 'violates PodSecurity "[^"]*"' <<< "$out")"
  else
    fail "$(basename "$f") не отклонён PodSecurity: $out"
  fi
done

echo
echo "OPA Gatekeeper"
kubectl get validatingwebhookconfiguration gatekeeper-validating-webhook-configuration >/dev/null 2>&1 \
  && ok "вебхук validation.gatekeeper.sh зарегистрирован" || fail "вебхук Gatekeeper не найден"
kubectl -n gatekeeper-system wait --for=condition=Ready pod -l control-plane=controller-manager --timeout=60s >/dev/null 2>&1 \
  && ok "контроллер Gatekeeper запущен" || fail "контроллер Gatekeeper не готов"
for t in k8sdenyprivileged k8sdenyhostpath k8srunasnonroot; do
  [ "$(kubectl get constrainttemplate "$t" -o jsonpath='{.status.created}' 2>/dev/null)" = true ] \
    && ok "шаблон $t создан" || fail "шаблон $t не создан"
done
for c in k8sdenyprivileged/deny-privileged k8sdenyhostpath/deny-hostpath k8srunasnonroot/require-non-root; do
  action="$(kubectl get "$c" -o jsonpath='{.spec.enforcementAction}' 2>/dev/null)"
  [ "$action" = deny ] && ok "ограничение ${c#*/}: $action" || fail "ограничение ${c#*/}: ${action:-нет}"
done

kubectl delete namespace gatekeeper-check --ignore-not-found --wait=true >/dev/null
kubectl create namespace gatekeeper-check --dry-run=client -o yaml \
  | kubectl label --local -f - pod-security.kubernetes.io/enforce=privileged -o yaml \
  | kubectl apply -f - >/dev/null
declare -A expected=(
  [01-privileged-pod.yaml]=deny-privileged
  [02-hostpath-pod.yaml]=deny-hostpath
  [03-root-user-pod.yaml]=require-non-root
)
for f in "$base"/insecure-manifests/*.yaml; do
  name="$(basename "$f")"
  out="$(sed 's/namespace: audit-zone/namespace: gatekeeper-check/' "$f" \
    | kubectl apply --dry-run=server -f - 2>&1)"
  if grep -q 'validation.gatekeeper.sh' <<< "$out" && grep -q "\[${expected[$name]}\]" <<< "$out"; then
    ok "$name отклонён Gatekeeper: $(grep -o '\[[a-z-]*\]' <<< "$out" | sort -u | tr '\n' ' ')"
  else
    fail "$name не отклонён ограничением ${expected[$name]}: $out"
  fi
done
kubectl delete namespace gatekeeper-check --wait=true >/dev/null

echo
if [ "$failed" -eq 0 ]; then
  echo "Все проверки пройдены"
else
  echo "Проверок с ошибкой: $failed"
  exit 1
fi
