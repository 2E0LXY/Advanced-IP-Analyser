#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_root="$project_root/build/deb-root"
output_dir="$project_root/dist"

rm -rf "$package_root"
mkdir -p "$package_root" "$output_dir"
cp -a "$project_root/packaging/debian/." "$package_root/"
mkdir -p "$package_root/usr/lib/advanced-ip-analyser" "$package_root/usr/share/doc/advanced-ip-analyser"
cp -a "$project_root/src/ip_analyser" "$package_root/usr/lib/advanced-ip-analyser/"
cp "$project_root/README.md" "$package_root/usr/share/doc/advanced-ip-analyser/README.md"
cp "$project_root/LICENSE" "$package_root/usr/share/doc/advanced-ip-analyser/copyright"
chmod 0755 "$package_root/usr/bin/advanced-ip-analyser" "$package_root/usr/bin/advanced-ip-analyser-gui"
chmod 0755 "$package_root/DEBIAN"
find "$package_root" -type d -exec chmod 0755 {} +
find "$package_root" -type f ! -path '*/usr/bin/*' -exec chmod 0644 {} +

fakeroot dpkg-deb --build --root-owner-group "$package_root" "$output_dir/advanced-ip-analyser_0.2.0_all.deb"
