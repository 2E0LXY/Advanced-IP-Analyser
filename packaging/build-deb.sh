#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_root="$project_root/build/deb-root"
output_dir="$project_root/dist"
version=$(PYTHONPATH="$project_root/src" python3 -c 'from ip_analyser import __version__; print(__version__)')

printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
    echo "Invalid application version: $version" >&2
    exit 2
}

rm -rf "$package_root"
mkdir -p "$package_root" "$output_dir"
cp -a "$project_root/packaging/debian/." "$package_root/"
mkdir -p "$package_root/usr/lib/advanced-ip-analyser" \
         "$package_root/usr/share/doc/advanced-ip-analyser" \
         "$package_root/usr/share/icons/hicolor/scalable/apps" \
         "$package_root/usr/share/man/man1"
cp -a "$project_root/src/ip_analyser" "$package_root/usr/lib/advanced-ip-analyser/"
cp "$project_root/README.md" "$package_root/usr/share/doc/advanced-ip-analyser/README.md"
cp "$project_root/CHANGELOG.md" "$package_root/usr/share/doc/advanced-ip-analyser/CHANGELOG.md"
cp "$project_root/packaging/copyright" "$package_root/usr/share/doc/advanced-ip-analyser/copyright"
cp "$project_root/packaging/changelog.Debian" "$package_root/usr/share/doc/advanced-ip-analyser/changelog"
cp "$project_root/packaging/advanced-ip-analyser.1" "$package_root/usr/share/man/man1/advanced-ip-analyser.1"
cp "$project_root/src/ip_analyser/assets/advanced-ip-analyser.svg" \
   "$package_root/usr/share/icons/hicolor/scalable/apps/advanced-ip-analyser.svg"
find "$package_root" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$package_root" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
chmod 0755 "$package_root/usr/bin/advanced-ip-analyser" "$package_root/usr/bin/advanced-ip-analyser-gui"
chmod 0755 "$package_root/DEBIAN"
find "$package_root" -type d -exec chmod 0755 {} +
find "$package_root" -type f ! -path '*/usr/bin/*' -exec chmod 0644 {} +
gzip -9n "$package_root/usr/share/doc/advanced-ip-analyser/changelog"
gzip -9n "$package_root/usr/share/man/man1/advanced-ip-analyser.1"
ln -s advanced-ip-analyser.1.gz "$package_root/usr/share/man/man1/advanced-ip-analyser-gui.1.gz"
installed_size=$(du -sk "$package_root/usr" | cut -f1)
sed -i "s/@VERSION@/$version/; s/@INSTALLED_SIZE@/$installed_size/" "$package_root/DEBIAN/control"

package="$output_dir/advanced-ip-analyser_${version}_all.deb"
rm -f "$package"
fakeroot dpkg-deb --build --root-owner-group "$package_root" "$package"
