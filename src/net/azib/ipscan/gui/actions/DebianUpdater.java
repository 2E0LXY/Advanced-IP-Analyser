package net.azib.ipscan.gui.actions;

import net.azib.ipscan.config.Labels;
import net.azib.ipscan.config.Version;
import net.azib.ipscan.gui.StatusBar;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Shell;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.regex.Pattern;

/** Downloads, verifies, and installs releases produced by this repository. */
public class DebianUpdater {
    private static final int TIMEOUT = 10_000;
    private static final long MAX_PACKAGE_SIZE = 100L * 1024 * 1024;
    private static final Pattern RELEASE = Pattern.compile("v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-.][A-Za-z0-9]+)*");
    private static final String RELEASES = Version.WEBSITE + "/releases/download/";

    public String latestRelease() throws IOException {
        var connection = connection(URI.create(Version.DOWNLOAD_URL));
        connection.setInstanceFollowRedirects(false);
        try {
            var status = connection.getResponseCode();
            if (status < 300 || status >= 400) throw new IOException("Latest release did not redirect: HTTP " + status);
            var location = connection.getHeaderField("Location");
            if (location == null || !location.contains("/releases/tag/")) throw new IOException("Missing release tag redirect");
            var tag = location.substring(location.lastIndexOf('/') + 1);
            if (!RELEASE.matcher(tag).matches()) throw new IOException("Invalid release tag");
            return tag;
        }
        finally {
            connection.disconnect();
        }
    }

    public boolean isNewer(String candidate, String current) {
        var a = numericParts(candidate);
        var b = numericParts(current);
        for (var i = 0; i < 3; i++) {
            var comparison = Integer.compare(a[i], b[i]);
            if (comparison != 0) return comparison > 0;
        }
        return false;
    }

    public void install(String tag, Shell shell, StatusBar statusBar, Runnable onFailure) {
        if (!RELEASE.matcher(tag).matches()) throw new IllegalArgumentException("Invalid release tag");
        var thread = new Thread(() -> {
            Path packageFile = null;
            try {
                setStatus(statusBar, Labels.getLabel("state.updateDownloading"));
                var version = tag.startsWith("v") ? tag.substring(1) : tag;
                var filename = "Advanced-IP-Analyser_" + version + "_amd64.deb";
                var base = RELEASES + tag + '/';
                packageFile = Files.createTempFile("advanced-ip-analyser-update-", ".deb");
                download(URI.create(base + filename), packageFile, MAX_PACKAGE_SIZE);
                var sums = downloadText(URI.create(base + "SHA256SUMS"), 64 * 1024);
                var expected = expectedDigest(sums, filename);
                var actual = sha256(packageFile);
                if (!MessageDigest.isEqual(expected.getBytes(), actual.getBytes()))
                    throw new IOException("Downloaded package checksum does not match the release");

                setStatus(statusBar, Labels.getLabel("state.updateInstalling"));
                var process = new ProcessBuilder("pkexec", "dpkg", "--install", packageFile.toString())
                    .inheritIO().start();
                if (process.waitFor() != 0) throw new IOException("Package installation was cancelled or failed");

                Display.getDefault().asyncExec(() -> {
                    try { new ProcessBuilder("/usr/bin/ipscan").start(); }
                    catch (IOException ignored) {}
                    if (!shell.isDisposed()) shell.dispose();
                });
            }
            catch (Exception e) {
                var detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                Display.getDefault().asyncExec(() -> {
                    statusBar.setStatusText(null);
                    if (shell.isDisposed()) return;
                    var box = new MessageBox(shell, SWT.ICON_ERROR | SWT.OK | SWT.SHEET);
                    box.setText(Version.NAME);
                    box.setMessage(Labels.getLabel("text.update.failed") + "\n\n" + detail);
                    box.open();
                    onFailure.run();
                });
            }
            finally {
                if (packageFile != null) try { Files.deleteIfExists(packageFile); } catch (IOException ignored) {}
            }
        }, "debian-updater");
        thread.setDaemon(true);
        thread.start();
    }

    static String expectedDigest(String sums, String filename) throws IOException {
        for (var line : sums.lines().toList()) {
            var fields = line.strip().split("\\s+", 2);
            if (fields.length == 2 && fields[1].replaceFirst("^[*]", "").equals(filename)
                && fields[0].matches("[0-9a-fA-F]{64}")) return fields[0].toLowerCase();
        }
        throw new IOException("Release checksum is missing");
    }

    private static void setStatus(StatusBar statusBar, String message) {
        Display.getDefault().asyncExec(() -> {
            if (!statusBar.isDisposed()) statusBar.setStatusText(message);
        });
    }

    private static int[] numericParts(String version) {
        var matcher = Pattern.compile("(?:v)?([0-9]+)\\.([0-9]+)\\.([0-9]+)").matcher(version);
        if (!matcher.find()) return new int[] {0, 0, 0};
        return new int[] {Integer.parseInt(matcher.group(1)), Integer.parseInt(matcher.group(2)), Integer.parseInt(matcher.group(3))};
    }

    private static String sha256(Path file) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(file)) {
            var buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) >= 0;) digest.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String downloadText(URI uri, long limit) throws IOException {
        var temp = Files.createTempFile("advanced-ip-analyser-checksum-", ".txt");
        try {
            download(uri, temp, limit);
            return Files.readString(temp);
        }
        finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void download(URI uri, Path destination, long limit) throws IOException {
        var connection = connection(uri);
        try {
            var length = connection.getContentLengthLong();
            if (length > limit) throw new IOException("Update download is too large");
            try (var input = connection.getInputStream(); var output = Files.newOutputStream(destination)) {
                var buffer = new byte[64 * 1024];
                long total = 0;
                for (int count; (count = input.read(buffer)) >= 0;) {
                    total += count;
                    if (total > limit) throw new IOException("Update download is too large");
                    output.write(buffer, 0, count);
                }
            }
        }
        finally {
            connection.disconnect();
        }
    }

    private static HttpURLConnection connection(URI uri) throws IOException {
        var connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setConnectTimeout(TIMEOUT);
        connection.setReadTimeout(TIMEOUT);
        connection.setRequestProperty("User-Agent", "Advanced-IP-Analyser/" + Version.getVersion());
        return connection;
    }
}
