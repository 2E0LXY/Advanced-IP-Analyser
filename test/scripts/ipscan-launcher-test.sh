#!/bin/sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/java" <<'EOF'
#!/bin/sh
exit "${FAKE_JAVA_STATUS:-0}"
EOF
chmod +x "$tmp/bin/java"

JAVA_HOME="$tmp" FAKE_JAVA_STATUS=0 sh ext/deb-bundle/usr/bin/ipscan

set +e
JAVA_HOME="$tmp" FAKE_JAVA_STATUS=23 sh ext/deb-bundle/usr/bin/ipscan
status=$?
set -e

test "$status" -eq 23
