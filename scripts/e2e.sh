#!/usr/bin/env bash
#
# End-to-end test for vault-plugin-secrets-gpg.
#
# Builds the plugin, brings up both Vault and OpenBao, then drives the identical
# lifecycle against each to prove the same binary works on both:
#   generate key -> sign/verify -> encrypt/decrypt -> rotate -> decrypt old
#   ciphertext -> export public key.
#
# Select engines with ENGINES (default "vault openbao"), e.g. ENGINES=openbao.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/test/docker-compose.yml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"
BINARY="vault-plugin-secrets-gpg"

MOUNT="gpg"
ENGINES="${ENGINES:-vault openbao}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }

cleanup() { blue "Tearing down containers"; ${COMPOSE} down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { red "FAIL: $*"; exit 1; }

wait_for() {
  local desc="$1"; shift
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "${WAIT_RETRIES:-90}" ] && fail "timed out waiting for ${desc}"
    sleep 2
  done
  green "ready: ${desc}"
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

run_engine() {
  local engine="$1" container="$2" cli="$3"
  blue "[${engine}] exercising the plugin"
  ex() { ${COMPOSE} exec -T "${container}" "${cli}" "$@"; }

  local sha; sha="$(sha256sum "${ROOT_DIR}/dist/${BINARY}" | awk '{print $1}')"
  ex plugin register -sha256="${sha}" secret "${BINARY}" >/dev/null || true
  ex secrets disable "${MOUNT}" >/dev/null 2>&1 || true
  ex secrets enable -path="${MOUNT}" "${BINARY}" >/dev/null
  green "[${engine}] plugin registered and mounted"

  # --- generate a key ---
  local pub
  pub="$(ex write -field=public_key "${MOUNT}/keys/app" algorithm=rsa-2048 identity='App <app@example.com>')"
  printf '%s' "${pub}" | grep -q 'BEGIN PGP PUBLIC KEY BLOCK' || fail "[${engine}] no armored public key returned"
  green "[${engine}] key generated; public key exported"

  # --- sign / verify ---
  local msg sig valid
  msg="$(b64 'ship it')"
  sig="$(ex write -field=signature "${MOUNT}/sign/app" input="${msg}")"
  valid="$(ex write -field=valid "${MOUNT}/verify/app" input="${msg}" signature="${sig}")"
  [ "${valid}" = "true" ] || fail "[${engine}] signature did not verify"
  green "[${engine}] sign/verify ok"

  # --- encrypt / decrypt roundtrip ---
  local ct pt secret="correct horse battery staple"
  ct="$(ex write -field=ciphertext "${MOUNT}/encrypt/app" plaintext="$(b64 "${secret}")")"
  pt="$(ex write -field=plaintext "${MOUNT}/decrypt/app" ciphertext="${ct}" | base64 -d)"
  [ "${pt}" = "${secret}" ] || fail "[${engine}] encrypt/decrypt roundtrip mismatch"
  green "[${engine}] encrypt/decrypt ok"

  # --- rotate, then decrypt the pre-rotation ciphertext ---
  local ver
  ver="$(ex write -field=latest_version "${MOUNT}/keys/app/rotate")"
  [ "${ver}" = "2" ] || fail "[${engine}] rotate did not bump to version 2"
  pt="$(ex write -field=plaintext "${MOUNT}/decrypt/app" ciphertext="${ct}" | base64 -d)"
  [ "${pt}" = "${secret}" ] || fail "[${engine}] old ciphertext failed to decrypt after rotation"
  green "[${engine}] rotation retains old versions"

  green "[${engine}] PASSED"
}

blue "Building plugin for linux/amd64"
OS=linux ARCH=amd64 PLUGIN_DIR="${ROOT_DIR}/dist" make -C "${ROOT_DIR}" build

blue "Starting Docker stack (vault + openbao)"
${COMPOSE} up -d --build

for engine in ${ENGINES}; do
  case "${engine}" in
    vault)   wait_for "vault"   ${COMPOSE} exec -T vault   vault status -address=http://127.0.0.1:8200; run_engine vault vault vault ;;
    openbao) wait_for "openbao" ${COMPOSE} exec -T openbao bao   status -address=http://127.0.0.1:8200; run_engine openbao openbao bao ;;
    *) fail "unknown engine: ${engine}" ;;
  esac
done

green "ALL END-TO-END CHECKS PASSED (${ENGINES})"
