# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
   - Кто: kubernetes-admin
   - Где: namespace=kube-system, resource=secrets, name=bootstrap-token-ryu4na, subresource=-
   - Что: verb=`get`, code=`404`, uri=`/api/v1/namespaces/kube-system/secrets/bootstrap-token-ryu4na?timeout=10s`
   - Почему подозрительно: Секреты часто содержат токены ServiceAccount, пароли, ключи доступа. Доступ к secrets в `kube-system` — частый признак попытки захвата контроля над кластером.

   - Кто: minikube-user (impersonate system:serviceaccount:secure-ops:monitoring)
   - Где: namespace=kube-system, resource=secrets, name=-, subresource=-
   - Что: verb=`list`, code=`403`, uri=`/api/v1/namespaces/kube-system/secrets?limit=500`
   - Почему подозрительно: Секреты часто содержат токены ServiceAccount, пароли, ключи доступа. Доступ к secrets в `kube-system` — частый признак попытки захвата контроля над кластером.

2. Привилегированные поды:
   - Кто: minikube-user
   - Где: namespace=secure-ops, resource=pods, name=privileged-pod, subresource=-
   - Что: создание pod с рисками ['privileged'], code=`201`
   - Комментарий: Privileged контейнер практически снимает ограничения изоляции и может дать доступ к ресурсам ноды (вплоть до root на хосте), что является сильным признаком компрометации.

3. Использование kubectl exec в чужом поде:
   - Кто: minikube-user
   - Где: namespace=kube-system, resource=pods, name=coredns-7d764666f9-5qktg, subresource=exec
   - Что делал: verb=`get` на subresource=`exec`, code=`101`
   - Почему подозрительно: `kubectl exec` в системные поды позволяет выполнять команды внутри компонентов кластера и часто используется злоумышленниками для разведки/закрепления.

4. Создание RoleBinding с правами cluster-admin:
   - Кто: minikube-user
   - Где: namespace=secure-ops, resource=rolebindings, name=escalate-binding, subresource=-
   - Что: создан RoleBinding `escalate-binding`, code=`201`
   - К чему привело: **потенциальная эскалация прав**. В текущем audit policy для RBAC-событий уровень `Metadata`, поэтому `roleRef` не записан в лог и мы не можем доказать, что это именно `cluster-admin` только по audit.
   - Почему подозрительно: Создание RoleBinding в `secure-ops` может использоваться для эскалации прав. В данном логе уровень аудита `Metadata`, поэтому roleRef не виден, но имя `escalate-binding` и контекст симуляции указывают на попытку повышения прав.

5. Удаление audit-policy.yaml:
   - Кто: minikube-user
   - Где: namespace=kube-system, resource=configmaps, name=audit-policy, subresource=-
   - Возможные последствия: ослабление аудита/скрытие следов; verb=`get`, code=`404`
   - Комментарий: Действия вокруг `audit-policy` выглядят как попытка ослабить аудит или скрыть следы. Даже неуспешные попытки (403/404) важны как индикатор.

   - Кто: minikube-user
   - Где: namespace=kube-system, resource=configmaps, name=audit-policy, subresource=-
   - Возможные последствия: ослабление аудита/скрытие следов; verb=`create`, code=`201`
   - Комментарий: Действия вокруг `audit-policy` выглядят как попытка ослабить аудит или скрыть следы. Даже неуспешные попытки (403/404) важны как индикатор.

   - Кто: minikube-user (impersonate admin)
   - Где: namespace=kube-system, resource=configmaps, name=audit-policy, subresource=-
   - Возможные последствия: ослабление аудита/скрытие следов; verb=`delete`, code=`403`
   - Комментарий: Действия вокруг `audit-policy` выглядят как попытка ослабить аудит или скрыть следы. Даже неуспешные попытки (403/404) важны как индикатор.

## Вывод
- В логе присутствуют признаки атакующей активности из симуляции: попытка доступа к `secrets` в `kube-system` (включая impersonation), запуск `privileged` pod, и `exec` в системный pod.
- Эти действия **могут считаться компрометацией** или попыткой компрометации: privileged pod + доступ к secrets + exec в kube-system дают высокий риск захвата ноды/кластера.
- RBAC-эскалация через RoleBinding зафиксирована как создание `escalate-binding`, но из-за уровня аудита `Metadata` нельзя подтвердить конкретный `roleRef` (например `cluster-admin`) по логу.

## Что можно считать компрометацией кластера
- Успешное чтение/листинг `secrets` в `kube-system` или других чужих namespace (code=200).
- Создание privileged pod / pod с hostPath/hostPID/hostNetwork/hostIPC.
- Создание RoleBinding/ClusterRoleBinding на `cluster-admin` для несанкционированного субъекта.
- `kubectl exec` в `kube-system` (или другие критичные namespace).
- Попытки отключить/изменить аудит (audit-policy tamper).

## Какие ошибки допускает политика RBAC
- Нет контроля/запрета на privileged workloads (нужны PSA `restricted` или Gatekeeper/Kyverno политики).
- Нет детектора/алерта на попытки `secrets list/get`, `pods/exec`, `rolebindings` с эскалацией.
- Аудит на RBAC-событиях записан на уровне `Metadata`, из-за чего теряются детали (`requestObject.roleRef`), что ухудшает расследование.

