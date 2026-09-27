#!/usr/bin/env bash
# Связывает пользователей с ролями. Права выдаются группам из сертификата
# пользователя (поле O), поэтому состав прав меняется выпуском сертификата
# с другими группами, а не правкой привязок.
# Использование: ./bind-roles.sh
set -euo pipefail

cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: propdev-cluster-admins
subjects:
  - kind: Group
    name: propdev:cluster-admins
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: propdev-security-auditors
subjects:
  - kind: Group
    name: propdev:security
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: propdev-security-auditor
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: propdev-cluster-configurators
subjects:
  - kind: Group
    name: propdev:devops
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: propdev-cluster-configurator
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: propdev-cluster-viewers
subjects:
  - kind: Group
    name: propdev:viewers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: propdev-cluster-viewer
  apiGroup: rbac.authorization.k8s.io
EOF

# Роли доменов действуют только в namespace своего домена
for ns in sales housing finance data; do
  cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: propdev-developers
  namespace: $ns
subjects:
  - kind: Group
    name: propdev:$ns-developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: propdev-namespace-developer
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: propdev-secrets-managers
  namespace: $ns
subjects:
  - kind: Group
    name: propdev:$ns-devops
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: propdev-secrets-manager
  apiGroup: rbac.authorization.k8s.io
EOF
done
