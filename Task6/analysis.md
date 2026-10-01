# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
   - Кто: `minikube-user` из группы `system:masters` (сертификат администратора кластера, адрес 192.168.49.1, `kubectl/v1.36.4`). Первый запрос выполнен от собственного имени, второй от имени `system:serviceaccount:secure-ops:monitoring` через `--as`. Перед ними от имени monitoring создан `SelfSubjectAccessReview`, это проверка `kubectl auth can-i get secrets`.
   - Где: namespace `kube-system`, `list secrets` (`/api/v1/namespaces/kube-system/secrets`). От имени администратора запрос выполнен (200), от имени monitoring отклонён (403). Секрета `default-token` в кластере нет, такие токены не создаются начиная с Kubernetes 1.24, поэтому команда из скрипта превратилась в запрос списка всех секретов.
   - Почему подозрительно: сервисному аккаунту мониторинга не нужны секреты, тем более в kube-system, где лежат токены и ключи компонентов кластера. Цепочка «проверить права, перечислить секреты, запросить их от имени сервисного аккаунта» - это разведка перед кражей учётных данных.

2. Привилегированные поды:
   - Кто: `minikube-user`
   - Комментарий: в namespace `secure-ops` создан под `privileged-pod` (alpine, `sleep 3600`) с `securityContext.privileged: true`. Запрос разрешён, в namespace действует уровень PodSecurity `privileged` (аннотация `pod-security.kubernetes.io/enforce-policy: privileged:latest`), поэтому ограничений нет. Привилегированный контейнер получает все capabilities и доступ к устройствам узла, из него можно выйти на узел и прочитать данные kubelet и других подов. Рядом создан `attacker-pod` (alpine, `sleep 3600`) без повышенных прав как точка присутствия в кластере.

3. Использование kubectl exec в чужом поде:
   - Кто: `minikube-user`
   - Что делал: запустил `cat /etc/resolv.conf` в поде `coredns-7d764666f9-jx75m` в `kube-system` (в requestURI `command=cat&command=%2Fetc%2Fresolv.conf`). Запрос разрешён (101 Switching Protocols), команда не выполнилась, потому что в образе CoreDNS нет `cat`. Событие записано с глаголом `get`, а не `create`: kubectl открывает exec через WebSocket, поэтому проверка `verb=="create"` его не находит. Exec в системный под даёт выполнение команд от имени компонента кластера и доступ к токену его сервисного аккаунта.

4. Создание RoleBinding с правами cluster-admin:
   - Кто: `minikube-user`
   - К чему привело: RoleBinding `escalate-binding` в `secure-ops` связал ClusterRole `cluster-admin` с сервисным аккаунтом `monitoring`. Внутри namespace аккаунт получил все права: `kubectl auth can-i` от его имени отвечает `yes` на чтение секретов, создание подов, exec и создание RoleBinding в `secure-ops` и `no` на секреты kube-system и узлы. Вместе с отсутствием ограничений PodSecurity это путь на весь кластер: токеном monitoring можно создать привилегированный под и выйти на узел. Привязка работает независимо от учётной записи администратора и остаётся закладкой для повторного входа. Признаков согласования в журнале нет.

5. Удаление audit-policy.yaml:
   - Кто: попытка от имени `admin` через `--as=admin`, инициатор - владелец учётной записи `minikube-user`.
   - Возможные последствия: события в audit.log нет. `kubectl delete -f /etc/kubernetes/audit-policy.yaml` завершился на клиенте ошибкой `the path "/etc/kubernetes/audit-policy.yaml" does not exist`, запрос к API не отправлялся. Политика аудита - файл на узле control plane, а не объект Kubernetes, через API её не удалить. Все совпадения по `audit-policy` в логе - это аргумент `--audit-policy-file` в объекте пода kube-apiserver и configmap `kubeadm-config`. С доступом к узлу, например из привилегированного пода, политику можно удалить или заменить и перезапустить kube-apiserver: аудит отключится или перестанет записывать нужные события, и дальнейшие действия не оставят следов. Такое изменение обнаруживается только контролем целостности файлов на узле и по прекращению потока событий в системе сбора журналов.

## Вывод

Все действия выполнены за несколько секунд одной учётной записью `minikube-user` с одного адреса. Это сертификат из группы `system:masters`, по журналу нельзя определить, какой человек за ним стоит, а сами действия выглядят как работа злоумышленника с украденными учётными данными администратора.

Вредоносными считаются все пять событий. Компрометацией кластера считается создание привилегированного пода и RoleBinding на `cluster-admin`. Первое даёт выход на узел, второе закрепляет доступ через сервисный аккаунт, который не зависит от учётной записи администратора. Кластер нужно считать скомпрометированным. Первоочередные действия:
- удалить `privileged-pod`, `attacker-pod` и `escalate-binding`;
- выпустить заново токены сервисных аккаунтов `secure-ops`;
- проверить узел;
- заменить сертификат администратора. Отозвать сертификат `system:masters` средствами RBAC нельзя, поможет только ротация CA кластера.

Ошибки политики RBAC:
- Повседневная работа идёт под сертификатом `system:masters`. Эта группа обходит RBAC полностью: в событиях у разрешённых запросов пустое поле `authorization.k8s.io/reason`, проверка ролей не выполнялась.
- Учётная запись администратора может выдавать себя за любого пользователя и сервисный аккаунт (`--as`), право impersonate ничем не ограничено.
- Привязку к `cluster-admin` создала учётная запись из `system:masters`, на которую не действует защита RBAC от повышения привилегий (проверка прав `bind` и `escalate`). Запрета на привязку мощных ролей к сервисным аккаунтам и процедуры согласования таких привязок нет.
- Для kube-system нет отдельных прав: exec в системные поды доступен той же учётной записи, что работает с прикладными namespace.
- Сервисный аккаунт monitoring создан без роли с минимальными правами и сразу получил `cluster-admin` в namespace.

Рядом с RBAC две проблемы конфигурации. В namespace нет ограничений PodSecurity, поэтому привилегированный под создаётся без препятствий. Политика аудита пишет секреты на уровне RequestResponse, то есть при чтении секрета его значение попадает в журнал, и журнал аудита сам становится хранилищем секретов.

## Как получен audit.log

Политика аудита лежит на хосте и монтируется в узел minikube внутрь `/etc/ssl/certs`, этот каталог kube-apiserver видит. Лог пишется в `/var/log/audit.log` внутри контейнера kube-apiserver:

```bash
minikube start --driver=docker \
  --mount --mount-string="$PWD/audit:/etc/ssl/certs/audit" \
  --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit/audit-policy.yaml \
  --extra-config=apiserver.audit-log-path=/var/log/audit.log

minikube ssh -- 'sudo docker cp $(sudo docker ps -q -f name=k8s_kube-apiserver):/var/log/audit.log /tmp/audit.log && sudo chmod 644 /tmp/audit.log'
minikube cp minikube:/tmp/audit.log audit.log
python3 filter-audit.py audit.log -o audit-extract.json --since 2026-09-27T12:42:13Z
```

В политике из задания два исправления. Правило `group: "*"` kube-apiserver 1.35 не принимает и не запускается, общее правило записано как `level: Metadata` без списка ресурсов. `roles` и `rolebindings` перенесены в группу `rbac.authorization.k8s.io`, в группе `""` их нет, и тело RoleBinding не попало бы в журнал.
