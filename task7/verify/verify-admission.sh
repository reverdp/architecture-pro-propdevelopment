#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="audit-zone"

ok(){ echo " $*"; }
fail(){ echo " $*" 1>&2; exit 1; }

# kubectl preflight (важно для Git Bash на Windows)
if command -v kubectl >/dev/null 2>&1; then
  : # ok
elif command -v kubectl.exe >/dev/null 2>&1; then
  kubectl(){ kubectl.exe "$@"; }
else
  fail "kubectl не найден в PATH внутри bash. Проверь установку/переменные окружения."
fi

echo "== Debug: kubectl path/context =="
command -v kubectl || true
kubectl version --client || true
kubectl config current-context || true
echo

expect_ok(){
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then ok "$name"
  else echo "$out" 1>&2; fail "$name (ожидали успех)"; fi
}

expect_fail(){
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "$out" 1>&2; fail "$name (ожидали отказ)"
  else ok "$name"; fi
}

expect_fail_contains(){
  local name="$1" needle="$2"; shift 2
  if out="$("$@" 2>&1)"; then echo "$out" 1>&2; fail "$name (ожидали отказ)"
  else
    echo "$out" | grep -qi "$needle" || { echo "$out" 1>&2; fail "$name (не нашли текст: $needle)"; }
    ok "$name"
  fi
}

echo "== Проверка базовых условий =="
if ! out="$(kubectl get ns "$NS" 2>&1)"; then
  echo "$out" 1>&2
  fail "Namespace $NS не найден ИЛИ kubectl смотрит не в тот кластер/контекст."
fi

labels="$(kubectl get ns "$NS" -o jsonpath="{.metadata.labels}" 2>/dev/null || true)"
echo "$labels" | grep -q "pod-security.kubernetes.io/enforce" || fail "В namespace $NS нет PSA-лейблов pod-security.*"

echo
echo "== Gatekeeper должен быть установлен и Ready =="
expect_ok "gatekeeper-system namespace" kubectl get ns gatekeeper-system
expect_ok "gatekeeper-controller-manager Ready" kubectl -n gatekeeper-system rollout status deploy/gatekeeper-controller-manager
expect_ok "gatekeeper-audit Ready" kubectl -n gatekeeper-system rollout status deploy/gatekeeper-audit

echo
echo "== Проверка: insecure-манифесты отклоняются =="
expect_fail "insecure privileged (dry-run server)" kubectl apply --dry-run=server -f "$ROOT/insecure-manifests/01-privileged-pod.yaml"
expect_fail "insecure hostPath (dry-run server)" kubectl apply --dry-run=server -f "$ROOT/insecure-manifests/02-hostpath-pod.yaml"
expect_fail "insecure root user (dry-run server)" kubectl apply --dry-run=server -f "$ROOT/insecure-manifests/03-root-user-pod.yaml"

echo
echo "== Проверка: secure-манифесты проходят =="
expect_ok "secure 01 (dry-run server)" kubectl apply --dry-run=server -f "$ROOT/secure-manifests/01-secure.yaml"
expect_ok "secure 02 (dry-run server)" kubectl apply --dry-run=server -f "$ROOT/secure-manifests/02-secure.yaml"
expect_ok "secure 03 (dry-run server)" kubectl apply --dry-run=server -f "$ROOT/secure-manifests/03-secure.yaml"

echo
echo "== Дифференциальные тесты: PSA vs Gatekeeper =="

echo "-- 1) PSA-only: нарушаем allowPrivilegeEscalation (Gatekeeper не проверяет), ожидаем отказ PSA"
cat <<EOF | expect_fail_contains "PSA-only violation rejected" "podsecurity" kubectl apply --dry-run=server -f -
apiVersion: v1
kind: Pod
metadata:
  name: psa-only-violation
  namespace: audit-zone
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh","-c","sleep 3600"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
      # намеренно НЕ ставим allowPrivilegeEscalation: false
EOF

echo "-- 2) Gatekeeper-only: НЕ ставим readOnlyRootFilesystem (PSA это не требует), ожидаем отказ Gatekeeper"
cat <<EOF | expect_fail_contains "Gatekeeper-only violation rejected" "readonlyrootfilesystem" kubectl apply --dry-run=server -f -
apiVersion: v1
kind: Pod
metadata:
  name: gatekeeper-only-violation
  namespace: audit-zone
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh","-c","sleep 3600"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      # намеренно НЕ ставим readOnlyRootFilesystem: true
EOF

ok "verify-admission.sh: все проверки пройдены"