#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-audit-zone}"

echo "== Debug: kubectl path/context =="
command -v kubectl >/dev/null || { echo "kubectl not found"; exit 1; }
kubectl version --client || true
kubectl config current-context || true
echo "Namespace: ${NS}"
echo

pass() { echo "✅ $*"; }
fail() { echo "❌ $*"; exit 1; }

ensure_ns() {
  if ! kubectl get ns "${NS}" >/dev/null 2>&1; then
    kubectl create ns "${NS}" >/dev/null
    pass "namespace ${NS} created"
  fi
}

create_dry_run_file() {
  local file="$1"
  kubectl -n "${NS}" create --dry-run=server -f "${file}"
}

stdin_to_tmpfile() {
  local tmp
  tmp="$(mktemp -t admission-XXXXXX.yaml)"
  cat > "${tmp}"
  if [[ ! -s "${tmp}" ]]; then
    rm -f "${tmp}"
    echo "❌ Empty YAML input (nothing piped into validator)" >&2
    exit 2
  fi
  echo "${tmp}"
}

expect_allow_yaml() {
  local desc="$1"
  local tmp
  tmp="$(stdin_to_tmpfile)"

  echo "-- allow: ${desc}"
  if create_dry_run_file "${tmp}" >/dev/null 2>&1; then
    pass "${desc} allowed"
    rm -f "${tmp}"
  else
    echo "---- kubectl error ----"
    create_dry_run_file "${tmp}" || true
    rm -f "${tmp}"
    fail "${desc} should be allowed, but was rejected"
  fi
}

expect_deny_yaml() {
  local desc="$1"
  local tmp
  tmp="$(stdin_to_tmpfile)"

  echo "-- deny: ${desc}"
  if create_dry_run_file "${tmp}" >/dev/null 2>&1; then
    rm -f "${tmp}"
    fail "${desc} should be rejected, but was allowed"
  else
    rm -f "${tmp}"
    pass "${desc} rejected (expected)"
  fi
}

echo "== Проверка базовых условий =="
ensure_ns

echo "== Gatekeeper (опционально) =="
if kubectl get ns gatekeeper-system >/dev/null 2>&1; then
  pass "gatekeeper-system namespace exists"
  kubectl -n gatekeeper-system get pods 2>/dev/null || true
else
  echo "ℹ️ gatekeeper-system namespace не найден (если используешь только PSA — может быть нормально)"
fi
echo

echo "== Проверка: insecure-манифесты отклоняются (dry-run server) =="

# 1) privileged
cat <<'YAML' | expect_deny_yaml "insecure privileged"
apiVersion: v1
kind: Pod
metadata:
  generateName: insecure-privileged-
spec:
  containers:
  - name: c
    image: busybox:1.36
    command: ["sh","-c","sleep 3600"]
    securityContext:
      privileged: true
YAML

# 2) hostPath
cat <<'YAML' | expect_deny_yaml "insecure hostPath"
apiVersion: v1
kind: Pod
metadata:
  generateName: insecure-hostpath-
spec:
  containers:
  - name: c
    image: busybox:1.36
    command: ["sh","-c","sleep 3600"]
    volumeMounts:
    - name: hp
      mountPath: /host
  volumes:
  - name: hp
    hostPath:
      path: /
      type: Directory
YAML

# 3) PSA-only: allowPrivilegeEscalation=true
cat <<'YAML' | expect_deny_yaml "insecure allowPrivilegeEscalation"
apiVersion: v1
kind: Pod
metadata:
  generateName: insecure-ape-
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: c
    image: busybox:1.36
    command: ["sh","-c","sleep 3600"]
    securityContext:
      allowPrivilegeEscalation: true
      capabilities:
        drop: ["ALL"]
YAML

echo
echo "== Проверка: secure-манифесты проходят (dry-run server) =="

secure_pod() {
  local prefix="$1"
  cat <<YAML
apiVersion: v1
kind: Pod
metadata:
  generateName: ${prefix}-
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: c
    image: busybox:1.36
    command: ["sh","-c","sleep 3600"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
YAML
}

secure_pod "secure-01" | expect_allow_yaml "secure 01"
secure_pod "secure-02" | expect_allow_yaml "secure 02"
secure_pod "secure-03" | expect_allow_yaml "secure 03"

echo
echo "validate-security.sh: все проверки admission пройдены ✅"
