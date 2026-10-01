#!/usr/bin/env bash
# Создаёт пользователей кластера. Для каждого пользователя: ключ, запрос
# на сертификат с группами в поле O, подпись сертификата через
# CertificateSigningRequest и отдельный kubeconfig.
# Использование: ./create-users.sh [каталог для файлов, по умолчанию ./users]
set -euo pipefail

out="${1:-users}"
mkdir -p "$out"

# пользователь|группы через запятую
users=(
  "a.smirnov|propdev:cluster-admins"
  "e.volkova|propdev:security"
  "d.kozlov|propdev:devops,propdev:housing-devops"
  "m.ivanova|propdev:sales-developers"
  "s.orlov|propdev:housing-developers"
  "n.sokolova|propdev:viewers"
)

cluster="$(kubectl config view --minify -o jsonpath='{.clusters[0].name}')"
server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
kubectl config view --minify --flatten \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$out/ca.crt"

for entry in "${users[@]}"; do
  name="${entry%%|*}"
  groups="${entry#*|}"
  subject="/CN=$name"
  IFS=',' read -ra group_list <<< "$groups"
  for group in "${group_list[@]}"; do
    subject+="/O=$group"
  done

  openssl genrsa -out "$out/$name.key" 2048 2>/dev/null
  chmod 600 "$out/$name.key"
  openssl req -new -key "$out/$name.key" -subj "$subject" -out "$out/$name.csr"

  kubectl delete csr "$name" --ignore-not-found >/dev/null
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $name
spec:
  request: $(base64 -w0 < "$out/$name.csr")
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 31536000
  usages:
    - client auth
EOF
  kubectl certificate approve "$name" >/dev/null

  cert=""
  for _ in $(seq 1 30); do
    cert="$(kubectl get csr "$name" -o jsonpath='{.status.certificate}')"
    [ -n "$cert" ] && break
    sleep 1
  done
  [ -n "$cert" ] || { echo "сертификат для $name не выпущен" >&2; exit 1; }
  echo "$cert" | base64 -d > "$out/$name.crt"

  kc="$out/$name.kubeconfig"
  rm -f "$kc"
  kubectl config --kubeconfig "$kc" set-cluster "$cluster" --server "$server" \
    --certificate-authority "$out/ca.crt" --embed-certs >/dev/null
  kubectl config --kubeconfig "$kc" set-credentials "$name" \
    --client-certificate "$out/$name.crt" --client-key "$out/$name.key" --embed-certs >/dev/null
  kubectl config --kubeconfig "$kc" set-context "$name" --cluster "$cluster" --user "$name" >/dev/null
  kubectl config --kubeconfig "$kc" use-context "$name" >/dev/null
  chmod 600 "$kc"

  echo "$name: группы $groups, kubeconfig $kc"
done
