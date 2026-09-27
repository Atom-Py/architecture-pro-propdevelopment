# Задание 7. PodSecurity Admission и OPA Gatekeeper

## Состав

| Файл | Назначение |
| :- | :- |
| `01-create-namespace.yaml` | namespace `audit-zone` с уровнем PodSecurity `restricted` в режимах enforce, audit и warn |
| `insecure-manifests/` | манифесты с нарушениями: `privileged: true`, том `hostPath`, запуск от UID 0 |
| `secure-manifests/` | исправленные манифесты, проходят `restricted` и правила Gatekeeper |
| `gatekeeper/constraint-templates/` | шаблоны ограничений на Rego |
| `gatekeeper/constraints/` | ограничения в режиме `deny` для подов во всех namespace, кроме системных |
| `verify/verify-admission.sh` | проверка, что PodSecurity Admission и Gatekeeper включены и отклоняют небезопасные поды |
| `verify/validate-security.sh` | проверка безопасных подов, их настроек, аудита Gatekeeper и журнала аудита kube-apiserver |
| `audit-policy.yaml` | политика аудита kube-apiserver |

## Правила Gatekeeper

| Требование | Шаблон | Ограничение | Что проверяется |
| :- | :- | :- | :- |
| Нельзя использовать `privileged: true` | `privileged.yaml`, `K8sDenyPrivileged` | `deny-privileged` | `securityContext.privileged` у containers, initContainers и ephemeralContainers |
| Только `runAsNonRoot: true` | `runasnonroot.yaml`, `K8sRunAsNonRoot` | `require-non-root` | `runAsNonRoot: true` у контейнера или у пода, если контейнер его не задаёт; `runAsUser: 0` запрещён |
| `readOnlyRootFilesystem: true` обязательно | `runasnonroot.yaml`, параметр `requireReadOnlyRootFilesystem` | `require-non-root` | `readOnlyRootFilesystem: true` у каждого контейнера |
| `hostPath` запрещён | `hostpath.yaml`, `K8sDenyHostPath` | `deny-hostpath` | тома пода с `hostPath` |

Требование к `readOnlyRootFilesystem` реализовано в шаблоне `runasnonroot.yaml`, потому что структура задания предусматривает три шаблона. Проверка включается параметром ограничения.

## Запуск

Проверялось на minikube v1.38.1, Kubernetes v1.35.1, Gatekeeper 3.23.1. Нужны minikube с драйвером docker, kubectl, helm и jq. Команды выполняются из каталога `Task7`.

1. Кластер с политикой аудита. Каталог с `audit-policy.yaml` монтируется в узел внутрь `/etc/ssl/certs`, этот каталог kube-apiserver видит, лог пишется в `/var/log/audit.log` контейнера kube-apiserver:

   ```bash
   minikube start --driver=docker \
     --mount --mount-string="$(pwd):/etc/ssl/certs/audit" \
     --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit/audit-policy.yaml \
     --extra-config=apiserver.audit-log-path=/var/log/audit.log
   ```

2. Gatekeeper:

   ```bash
   helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
   helm install gatekeeper gatekeeper/gatekeeper --version 3.23.1 \
     --namespace gatekeeper-system --create-namespace --wait
   ```

3. Namespace, шаблоны и ограничения:

   ```bash
   kubectl apply -f 01-create-namespace.yaml
   kubectl apply -f gatekeeper/constraint-templates/
   kubectl wait --for=jsonpath='{.status.created}'=true constrainttemplate --all --timeout=120s
   kubectl apply -f gatekeeper/constraints/
   ```

4. Небезопасные манифесты отклоняются:

   ```bash
   kubectl apply -f insecure-manifests/
   ```

   ```
   Error from server (Forbidden): error when creating "insecure-manifests/01-privileged-pod.yaml": pods "pod-privileged" is forbidden: violates PodSecurity "restricted:latest": privileged (container "nginx" must not set securityContext.privileged=true), ...
   Error from server (Forbidden): error when creating "insecure-manifests/02-hostpath-pod.yaml": pods "pod-hostpath" is forbidden: violates PodSecurity "restricted:latest": ..., restricted volume types (volume "host-etc" uses restricted volume type "hostPath"), ...
   Error from server (Forbidden): error when creating "insecure-manifests/03-root-user-pod.yaml": pods "pod-root-user" is forbidden: violates PodSecurity "restricted:latest": ..., runAsUser=0 (container "nginx" must not set runAsUser=0), ...
   ```

5. Проверки:

   ```bash
   ./verify/verify-admission.sh
   ./verify/validate-security.sh
   ```

   `validate-security.sh` создаёт поды из `secure-manifests/` в `audit-zone`.

## Результат проверок

`verify-admission.sh`:

```
PodSecurity Admission
  OK    audit-zone: enforce=restricted
  OK    audit-zone: audit=restricted
  OK    audit-zone: warn=restricted
  OK    01-privileged-pod.yaml отклонён: violates PodSecurity "restricted:latest"
  OK    02-hostpath-pod.yaml отклонён: violates PodSecurity "restricted:latest"
  OK    03-root-user-pod.yaml отклонён: violates PodSecurity "restricted:latest"

OPA Gatekeeper
  OK    вебхук validation.gatekeeper.sh зарегистрирован
  OK    контроллер Gatekeeper запущен
  OK    шаблон k8sdenyprivileged создан
  OK    шаблон k8sdenyhostpath создан
  OK    шаблон k8srunasnonroot создан
  OK    ограничение deny-privileged: deny
  OK    ограничение deny-hostpath: deny
  OK    ограничение require-non-root: deny
  OK    01-privileged-pod.yaml отклонён Gatekeeper: [deny-privileged] [require-non-root]
  OK    02-hostpath-pod.yaml отклонён Gatekeeper: [deny-hostpath] [require-non-root]
  OK    03-root-user-pod.yaml отклонён Gatekeeper: [require-non-root]

Все проверки пройдены
```

`validate-security.sh`:

```
Безопасные манифесты
  OK    01-secure.yaml проходит Gatekeeper
  OK    02-secure.yaml проходит Gatekeeper
  OK    03-secure.yaml проходит Gatekeeper
  OK    01-secure.yaml принят в audit-zone: pod/pod-privileged-fixed created
  OK    02-secure.yaml принят в audit-zone: pod/pod-hostpath-fixed created
  OK    03-secure.yaml принят в audit-zone: pod/pod-root-user-fixed created
  OK    поды audit-zone в состоянии Ready

Настройки запущенных подов
  OK    pod-hostpath-fixed: privileged нет, runAsNonRoot, UID не 0, rootfs только чтение, hostPath нет
  OK    pod-privileged-fixed: privileged нет, runAsNonRoot, UID не 0, rootfs только чтение, hostPath нет
  OK    pod-root-user-fixed: privileged нет, runAsNonRoot, UID не 0, rootfs только чтение, hostPath нет

Аудит Gatekeeper
  OK    deny-privileged: нарушений 0, аудит 2026-09-27T13:13:17Z
  OK    deny-hostpath: нарушений 0, аудит 2026-09-27T13:13:17Z
  OK    require-non-root: нарушений 0, аудит 2026-09-27T13:13:17Z

Журнал аудита kube-apiserver
  OK    отказов по подам audit-zone: 6, из них с --dry-run=server: 3; создано подов: 3
        pod-hostpath: pods "pod-hostpath" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false
        pod-privileged: pods "pod-privileged" is forbidden: violates PodSecurity "restricted:latest": privileged (container "nginx" mu
        pod-root-user: pods "pod-root-user" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false

Все проверки пройдены
```

Шесть отказов в журнале аудита: три от `kubectl apply` из шага 4 и три от проверки с `--dry-run=server` в `verify-admission.sh`.

## Порядок срабатывания admission controllers

PodSecurity Admission - встроенный плагин kube-apiserver и выполняется раньше вебхука Gatekeeper. В `audit-zone` небезопасный под отклоняет PodSecurity, до Gatekeeper запрос не доходит. Поэтому `verify-admission.sh` проверяет Gatekeeper отдельно, в служебном namespace `gatekeeper-check` с уровнем `privileged`, где PodSecurity ничего не запрещает. Ответ там приходит от вебхука `validation.gatekeeper.sh` со списком сработавших ограничений. Ограничения Gatekeeper действуют во всех namespace, кроме `kube-system`, `kube-public`, `kube-node-lease` и `gatekeeper-system`, поэтому защищают и namespace без меток PodSecurity.

## Аудит

- **Gatekeeper.** Раз в минуту проверяет существующие поды на соответствие ограничениям, результат лежит в `status.totalViolations` и `status.violations` ограничения: `kubectl get constraints`.
- **PodSecurity.** Режимы `audit` и `warn` на `audit-zone` добавляют нарушения уровня `restricted` в аннотации событий журнала аудита и в предупреждения kubectl.
- **`audit-policy.yaml`.** Записывает:
  - создание, изменение и удаление подов в `audit-zone` на уровне RequestResponse: видны манифест и причина отказа;
  - изменения шаблонов и ограничений Gatekeeper, меток namespace и RBAC;
  - секреты и configmap только на уровне Metadata, чтобы их значения не попадали в журнал.

  Отказы можно посмотреть так:

  ```bash
  minikube ssh -- 'sudo docker cp $(sudo docker ps -q -f name=k8s_kube-apiserver):/var/log/audit.log /tmp/audit.log && sudo chmod 644 /tmp/audit.log'
  minikube cp minikube:/tmp/audit.log audit.log
  jq 'select(.objectRef.namespace=="audit-zone" and .responseStatus.code==403) | {name: .objectRef.name, message: .responseStatus.message}' audit.log
  ```
