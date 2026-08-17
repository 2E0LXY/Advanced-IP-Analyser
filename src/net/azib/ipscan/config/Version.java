/*
  This is a part of Angry IP Scanner source.
 */
package net.azib.ipscan.config;

import java.util.jar.JarFile;
import java.util.logging.Level;

/**
 * Class with accessors to version information of the program.
 *
 * @author Anton Keks
 */
public class Version {
	public static final String NAME = "Advanced IP Analyser";
	
	public static final String COPYLEFT = "© 2026 Anton Keks and Advanced IP Analyser contributors";
	
	public static final String WEBSITE = "https://github.com/2E0LXY/Advanced-IP-Analyser";

	public static final String FAQ_URL = WEBSITE + "/blob/main/docs/DEBIAN13.md";

	public static final String PRIVACY_URL = WEBSITE + "/blob/main/PRIVACY.md";

	public static final String FULL_LICENSE_URL = "https://www.gnu.org/licenses/gpl-2.0.html";

	public static final String PLUGINS_URL = WEBSITE + "/blob/main/docs/ADVANCED_IP_SCANNER_REPLICA.md";
	
	public static final String DOWNLOAD_URL = WEBSITE + "/releases/latest";

	public static final String ISSUES_URL = WEBSITE + "/issues";

	public static final String IP_LOCATE_URL = "https://ipinfo.io/";

	public static final String LATEST_VERSION_URL = "https://raw.githubusercontent.com/2E0LXY/Advanced-IP-Analyser/main/VERSION";

	private static String version;
	private static String buildDate;
	
	/**
	 * @return version of currently running Angry IP Scanner (retrieved from the jar file)
	 */
	public static String getVersion() {
		if (version == null) {
			loadVersionFromJar();
		}
		return version;
	}
	
	/**
	 * @return build date of currently running Angry IP Scanner  (retrieved from the jar file)
	 */
	public static String getBuildDate() {
		if (buildDate == null) {
			loadVersionFromJar();
		}
		return buildDate;
	}

	private static void loadVersionFromJar() {
		try {
			var path = Version.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
			if (path.endsWith(".jar") || path.endsWith(".exe")) {
				var jarFile = new JarFile(path);
				var attrs = jarFile.getManifest().getMainAttributes();
				version = attrs.getValue("Version");
				buildDate = attrs.getValue("Build-Date");
				return;
			}
		}
		catch (Exception e) {
			LoggerFactory.getLogger().log(Level.WARNING, "Cannot obtain version", e);
		}
		version = "current";
		buildDate = "today";
	}
	
	public static String getFullName() {
		return NAME + " " + getVersion();
	}
}
