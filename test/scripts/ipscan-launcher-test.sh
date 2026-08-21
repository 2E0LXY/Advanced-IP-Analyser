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
touch "$tmp/application.jar"

JAVA_HOME="$tmp" IPSCAN_JAR="$tmp/application.jar" FAKE_JAVA_STATUS=0 sh ext/deb-bundle/usr/bin/ipscan

set +e
JAVA_HOME="$tmp" IPSCAN_JAR="$tmp/application.jar" FAKE_JAVA_STATUS=23 sh ext/deb-bundle/usr/bin/ipscan
status=$?
set -e

test "$status" -eq 23

set +e
JAVA_HOME="$tmp" IPSCAN_JAR="$tmp/missing.jar" sh ext/deb-bundle/usr/bin/ipscan 2> "$tmp/error"
status=$?
set -e
test "$status" -eq 1
grep -q 'application JAR was not found' "$tmp/error"
