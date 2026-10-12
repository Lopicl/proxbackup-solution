#!/usr/bin/env bash
# Starts a throwaway Proxmox Backup Server in Docker, creates a datastore and an
# admin API token, then runs the protocol end-to-end test (pkg/pbs/e2e_test.go).
#
#   ./scripts/e2e-pbs.sh          run tests, keep the container for inspection
#   KEEP=0 ./scripts/e2e-pbs.sh   remove container + volume afterwards
set -euo pipefail

IMAGE=${PBS_IMAGE:-ayufan/proxmox-backup-server:v4.2.0-1}
NAME=proxbackup-e2e
PORT=${PBS_PORT:-18007}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if ! docker inspect "$NAME" >/dev/null 2>&1; then
  docker run -d --name "$NAME" -p "$PORT:8007" --tmpfs /run -v proxbackup-e2e-data:/backups "$IMAGE" >/dev/null
fi
for _ in $(seq 1 60); do
  curl -sk -o /dev/null "https://localhost:$PORT/" && break
  sleep 2
done

docker exec "$NAME" sh -c '
  set -e
  proxmox-backup-manager datastore list | grep -q ds1 || {
    mkdir -p /backups/ds1 && chown backup:backup /backups/ds1
    proxmox-backup-manager datastore create ds1 /backups/ds1 >/dev/null
  }
  proxmox-backup-manager acl update / Admin --auth-id admin@pbs
  proxmox-backup-manager user delete-token admin@pbs e2e >/dev/null 2>&1 || true
' >/dev/null
docker exec "$NAME" proxmox-backup-manager user generate-token admin@pbs e2e | sed -n '/^Result:/,$p' | sed 's/^Result: //' > "$WORK/token.json"
docker exec "$NAME" proxmox-backup-manager acl update / Admin --auth-id 'admin@pbs!e2e'
FP=$(docker exec "$NAME" proxmox-backup-manager cert info | sed -n 's/^Fingerprint (sha256): //p')

PROXBACKUP_E2E_HOST="localhost:$PORT" PROXBACKUP_E2E_FINGERPRINT="$FP" PROXBACKUP_E2E_TOKEN_FILE="$WORK/token.json" \
  PROXBACKUP_E2E_STORE=ds1 go test ./pkg/pbs/ -run E2E -count=1 -v

if [ "${KEEP:-1}" = 0 ]; then
  docker rm -f "$NAME" >/dev/null && docker volume rm proxbackup-e2e-data >/dev/null
fi
