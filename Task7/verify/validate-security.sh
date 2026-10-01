#!/usr/bin/env bash
# Проверяет безопасные манифесты и итоговое состояние audit-zone:
#   1. манифесты из secure-manifests проходят Gatekeeper и PodSecurity,
#      поды создаются и переходят в Ready;
#   2. у запущенных подов нет privileged и hostPath, есть runAsNonRoot,
#      нет UID 0, корневая файловая система только для чтения;
#   3. аудит Gatekeeper не находит нарушений у существующих подов;
#   4. журнал аудита kube-apiserver (если кластер запущен в minikube с
#      audit-policy.yaml) содержит отказы по подам в audit-zone.
# Использование: ./verify/validate-security.sh
set -uo pipefail

base="$(cd "$(dirname "$0")/.." && pwd)"
failed=0

ok()   { echo "  OK    $*"; }
fail() { echo "  FAIL  $*"; failed=$((failed + 1)); }

echo "Безопасные манифесты"
kubectl delete namespace gatekeeper-check --ignore-not-found --wait=true >/dev/null
kubectl create namespace gatekeeper-check --dry-run=client -o yaml \
  | kubectl label --local -f - pod-security.kubernetes.io/enforce=privileged -o yaml \
  | kubectl apply -f - >/dev/null
for f in "$base"/secure-manifests/*.yaml; do
  out="$(sed 's/namespace: audit-zone/namespace: gatekeeper-check/' "$f" \
    | kubectl apply --dry-run=server -f - 2>&1)"
  [ $? -eq 0 ] && ok "$(basename "$f") проходит Gatekeeper" || fail "$(basename "$f") отклонён Gatekeeper: $out"
done
kubectl delete namespace gatekeeper-check --wait=true >/dev/null

for f in "$base"/secure-manifests/*.yaml; do
  out="$(kubectl apply -f "$f" 2>&1)"
  if [ $? -eq 0 ] && ! grep -qi warning <<< "$out"; then
    ok "$(basename "$f") принят в audit-zone: $out"
  else
    fail "$(basename "$f") не принят в audit-zone: $out"
  fi
done
kubectl -n audit-zone wait --for=condition=Ready pod --all --timeout=180s >/dev/null \
  && ok "поды audit-zone в состоянии Ready" || fail "поды audit-zone не перешли в Ready"

echo
echo "Настройки запущенных подов"
report="$(kubectl -n audit-zone get pods -o json | jq -r '
  .items[] | . as $pod | .spec.containers[] | [
    $pod.metadata.name,
    (if .securityContext.privileged == true then "privileged" else empty end),
    (if (.securityContext.runAsNonRoot // $pod.spec.securityContext.runAsNonRoot) != true
       then "нет runAsNonRoot" else empty end),
    (if (.securityContext.runAsUser // $pod.spec.securityContext.runAsUser) == 0
       then "UID 0" else empty end),
    (if .securityContext.readOnlyRootFilesystem != true
       then "нет readOnlyRootFilesystem" else empty end),
    (if ([$pod.spec.volumes[]? | select(.hostPath)] | length) > 0 then "hostPath" else empty end)
  ] | @tsv')"
while IFS=$'\t' read -r pod problems; do
  [ -z "$pod" ] && continue
  [ -z "$problems" ] && ok "$pod: privileged нет, runAsNonRoot, UID не 0, rootfs только чтение, hostPath нет" \
    || fail "$pod: $problems"
done <<< "$report"

echo
echo "Аудит Gatekeeper"
# аудит проходит раз в минуту, ждём результата после создания подов
for _ in $(seq 1 18); do
  pending=0
  for c in k8sdenyprivileged/deny-privileged k8sdenyhostpath/deny-hostpath k8srunasnonroot/require-non-root; do
    [ -z "$(kubectl get "$c" -o jsonpath='{.status.auditTimestamp}')" ] && pending=1
  done
  [ "$pending" -eq 0 ] && break
  sleep 10
done
for c in k8sdenyprivileged/deny-privileged k8sdenyhostpath/deny-hostpath k8srunasnonroot/require-non-root; do
  total="$(kubectl get "$c" -o jsonpath='{.status.totalViolations}')"
  stamp="$(kubectl get "$c" -o jsonpath='{.status.auditTimestamp}')"
  [ "${total:-x}" = 0 ] && ok "${c#*/}: нарушений 0, аудит $stamp" \
    || fail "${c#*/}: нарушений ${total:-нет данных}, аудит ${stamp:-не выполнялся}"
done

echo
echo "Журнал аудита kube-apiserver"
if command -v minikube >/dev/null && minikube status >/dev/null 2>&1; then
  tmp="$(mktemp)"
  minikube ssh -- 'sudo docker cp $(sudo docker ps -q -f name=k8s_kube-apiserver):/var/log/audit.log /tmp/audit.log >/dev/null && sudo chmod 644 /tmp/audit.log' >/dev/null 2>&1
  if minikube cp minikube:/tmp/audit.log "$tmp" >/dev/null 2>&1 && [ -s "$tmp" ]; then
    pods='select(.objectRef.resource=="pods" and .objectRef.namespace=="audit-zone"
                 and .verb=="create" and (.objectRef.subresource // "") == "")'
    denied="$(jq -c "$pods | select(.responseStatus.code==403)" "$tmp" | wc -l)"
    dry="$(jq -c "$pods | select(.responseStatus.code==403 and (.requestURI | test(\"dryRun\")))" "$tmp" | wc -l)"
    created="$(jq -c "$pods | select(.responseStatus.code==201 and (.requestURI | test(\"dryRun\") | not))" "$tmp" | wc -l)"
    [ "$denied" -gt 0 ] && ok "отказов по подам audit-zone: $denied, из них с --dry-run=server: $dry; создано подов: $created" \
      || fail "отказов по подам audit-zone в журнале нет"
    jq -r 'select(.objectRef.resource=="pods" and .objectRef.namespace=="audit-zone"
                  and .verb=="create" and .responseStatus.code==403)
           | "        \(.objectRef.name): \(.responseStatus.message | .[0:110])"' "$tmp" | sort -u
  else
    echo "  SKIP  журнал /var/log/audit.log не найден, кластер запущен без audit-policy.yaml"
  fi
  rm -f "$tmp"
else
  echo "  SKIP  кластер не в minikube, журнал проверяется вручную"
fi

echo
if [ "$failed" -eq 0 ]; then
  echo "Все проверки пройдены"
else
  echo "Проверок с ошибкой: $failed"
  exit 1
fi
