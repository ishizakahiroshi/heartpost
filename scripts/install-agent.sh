#!/bin/sh
# install-agent.sh — put heartpost-agent on a server and have cron run it.
#
# Runs on your machine, not on the server. It copies a binary and a config over
# ssh into a directory under the remote home, fixes the mode of the key file, and
# adds one crontab line. Nothing here needs root on the far side.
#
# It is meant to be re-runnable: the crontab line is keyed on a marker comment and
# replaced rather than appended, so running this twice does not schedule two agents.
#
#   ./scripts/install-agent.sh \
#       --host user@web01.example.com \
#       --binary ./dist/heartpost-agent-freebsd-amd64 \
#       --config ./config/agent.example.toml \
#       --secrets ./secrets/web01_agent_secrets.toml
#
# Build the binary for the target first, e.g. for shared hosting on FreeBSD:
#
#   GOOS=freebsd GOARCH=amd64 go build -o dist/heartpost-agent-freebsd-amd64 ./cmd/heartpost-agent

set -eu

HOST=""
PORT=""
BINARY=""
CONFIG=""
SECRETS=""
REMOTE_DIR="heartpost"
INTERVAL=5
INSTALL_CRON=1
DRY_RUN=0

usage() {
	cat <<'EOF'
usage: install-agent.sh --host <[user@]host> --binary <path> [options]

required:
  --host <[user@]host>   ssh destination
  --binary <path>        agent binary built for the target OS/arch

options:
  --port <n>             ssh port (default: ssh config / 22)
  --config <path>        agent.toml to upload
  --secrets <path>       agent_secrets.toml to upload (installed with mode 600)
  --remote-dir <path>    directory under the remote home (default: heartpost)
  --interval <minutes>   cron interval in minutes (default: 5)
  --no-cron              upload only, do not touch the crontab
  --dry-run              print what would run, change nothing
  -h, --help             this text

The monitor should treat a server as silent only after more than one missed run.
If you change --interval here, change the monitor's threshold to match.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--host) HOST="$2"; shift 2 ;;
	--port) PORT="$2"; shift 2 ;;
	--binary) BINARY="$2"; shift 2 ;;
	--config) CONFIG="$2"; shift 2 ;;
	--secrets) SECRETS="$2"; shift 2 ;;
	--remote-dir) REMOTE_DIR="$2"; shift 2 ;;
	--interval) INTERVAL="$2"; shift 2 ;;
	--no-cron) INSTALL_CRON=0; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

die() {
	echo "install-agent: $*" >&2
	exit 1
}

[ -n "$HOST" ] || die "--host is required"
[ -n "$BINARY" ] || die "--binary is required"
[ -f "$BINARY" ] || die "binary not found: $BINARY"
[ -z "$CONFIG" ] || [ -f "$CONFIG" ] || die "config not found: $CONFIG"
[ -z "$SECRETS" ] || [ -f "$SECRETS" ] || die "secrets not found: $SECRETS"

case "$INTERVAL" in
'' | *[!0-9]*) die "--interval must be a whole number of minutes" ;;
esac
[ "$INTERVAL" -ge 1 ] || die "--interval must be at least 1"

case "$REMOTE_DIR" in
/*) die "--remote-dir must be relative to the remote home directory" ;;
esac

SSH_OPTS=""
SCP_OPTS=""
if [ -n "$PORT" ]; then
	SSH_OPTS="-p $PORT"
	SCP_OPTS="-P $PORT"
fi

# The remote home is not assumed to be /home/<user>: shared hosting puts it
# anywhere. Everything is addressed relative to $HOME on the far side.
run_remote() {
	if [ "$DRY_RUN" -eq 1 ]; then
		echo "[dry-run] ssh $SSH_OPTS $HOST -- sh -c '$1'"
		return 0
	fi
	# shellcheck disable=SC2086
	ssh $SSH_OPTS "$HOST" /bin/sh -s <<EOF
set -eu
$1
EOF
}

copy_remote() {
	src="$1"
	dst="$2"
	if [ "$DRY_RUN" -eq 1 ]; then
		echo "[dry-run] scp $SCP_OPTS $src $HOST:$dst"
		return 0
	fi
	# shellcheck disable=SC2086
	scp $SCP_OPTS "$src" "$HOST:$dst"
}

echo "==> creating \$HOME/$REMOTE_DIR on $HOST"
run_remote "mkdir -p \"\$HOME/$REMOTE_DIR/bin\" \"\$HOME/$REMOTE_DIR/etc\" \"\$HOME/$REMOTE_DIR/var\"
chmod 700 \"\$HOME/$REMOTE_DIR/etc\""

echo "==> uploading agent binary"
# Upload beside the target and move into place, so a half-finished transfer never
# leaves a truncated binary that cron would try to run.
copy_remote "$BINARY" "$REMOTE_DIR/bin/heartpost-agent.new"
run_remote "chmod 700 \"\$HOME/$REMOTE_DIR/bin/heartpost-agent.new\"
mv \"\$HOME/$REMOTE_DIR/bin/heartpost-agent.new\" \"\$HOME/$REMOTE_DIR/bin/heartpost-agent\""

if [ -n "$CONFIG" ]; then
	echo "==> uploading agent.toml"
	copy_remote "$CONFIG" "$REMOTE_DIR/etc/agent.toml"
	run_remote "chmod 644 \"\$HOME/$REMOTE_DIR/etc/agent.toml\""
fi

if [ -n "$SECRETS" ]; then
	echo "==> uploading agent_secrets.toml (mode 600)"
	copy_remote "$SECRETS" "$REMOTE_DIR/etc/agent_secrets.toml"
	# The agent refuses to start unless this is 600. Set it here so that a fresh
	# install is never one forgotten chmod away from a key other tenants can read.
	run_remote "chmod 600 \"\$HOME/$REMOTE_DIR/etc/agent_secrets.toml\""
fi

if [ "$INSTALL_CRON" -eq 1 ]; then
	echo "==> installing crontab entry (every $INTERVAL minute(s))"
	# The marker is what makes this re-runnable: the old line is dropped and the
	# new one appended, instead of stacking another agent onto the schedule.
	run_remote "MARKER='# heartpost-agent (managed by install-agent.sh)'
LINE=\"*/$INTERVAL * * * * \\\"\$HOME/$REMOTE_DIR/bin/heartpost-agent\\\" --config \\\"\$HOME/$REMOTE_DIR/etc/agent.toml\\\" >/dev/null 2>&1\"
TMP=\$(mktemp)
crontab -l 2>/dev/null | grep -v -F \"\$MARKER\" | grep -v -F '$REMOTE_DIR/bin/heartpost-agent' > \"\$TMP\" || true
printf '%s\n%s\n' \"\$MARKER\" \"\$LINE\" >> \"\$TMP\"
crontab \"\$TMP\"
rm -f \"\$TMP\"
crontab -l | grep -F heartpost-agent"
else
	echo "==> skipping crontab (--no-cron)"
fi

echo "==> running once to check the installation"
run_remote "\"\$HOME/$REMOTE_DIR/bin/heartpost-agent\" --config \"\$HOME/$REMOTE_DIR/etc/agent.toml\" && echo 'agent exited 0'"

cat <<EOF

done. on $HOST:
  binary  \$HOME/$REMOTE_DIR/bin/heartpost-agent
  config  \$HOME/$REMOTE_DIR/etc/agent.toml
  log     see runtime.log_file in agent.toml

If the monitor shows nothing, read the log first: the agent writes one line per
collector and one line per POST. With monitor.endpoint empty it logs the whole
payload instead of sending, which is the quickest way to see what this host reports.
EOF
