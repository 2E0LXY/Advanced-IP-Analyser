/*
  This file is a part of Angry IP Scanner source code,
  see http://www.angryip.org/ for more information.
  Licensed under GPLv2.
 */
package net.azib.ipscan.gui.actions;

import net.azib.ipscan.config.OpenersConfig.Opener;
import net.azib.ipscan.config.Platform;
import net.azib.ipscan.core.ScanningResultList;
import net.azib.ipscan.core.UserErrorException;
import net.azib.ipscan.core.values.Empty;
import net.azib.ipscan.fetchers.FetcherRegistry;
import net.azib.ipscan.fetchers.HostnameFetcher;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.joining;

/**
 * OpenerLauncher
 *
 * @author Anton Keks
 */
public class OpenerLauncher {
	
	private final FetcherRegistry fetcherRegistry;
	private final ScanningResultList scanningResults;
	
	public OpenerLauncher(FetcherRegistry fetcherRegistry, ScanningResultList scanningResults) {
		this.fetcherRegistry = fetcherRegistry;
		this.scanningResults = scanningResults;
	}

	public void launch(Opener opener, int selectedItem) {
		// check for URLs
		if (isUrl(opener.execString)) {
			var openerString = prepareOpenerStringForItem(opener.execString, selectedItem);
			BrowserLauncher.openURL(openerString);
		}
		else {
			// run a process here
			try {
				if (opener.inTerminal) {
					var openerString = Platform.LINUX ? prepareShellCommandForItem(opener.execString, selectedItem) : prepareOpenerStringForItem(opener.execString, selectedItem);
					TerminalLauncher.launchInTerminal(openerString, opener.workingDir);
				}
				else {
					Runtime.getRuntime().exec(prepareCommandForItem(opener.execString, selectedItem), null, opener.workingDir);
				}
			}
			catch (UserErrorException e) {
				throw e;
			}
			catch (Exception e) {
				throw new UserErrorException("opener.failed", opener.execString);
			}
		}
	}

	private static boolean isUrl(String openerString) {
		return openerString.startsWith("http:") || openerString.startsWith("https:") || openerString.startsWith("ftp:") || openerString.startsWith("smb:") || openerString.startsWith("mailto:") || openerString.startsWith("\\\\");
	}

	String[] prepareCommandForItem(String command, int selectedItem) {
		return stream(splitCommand(command)).map(argument -> prepareOpenerStringForItem(argument, selectedItem)).toArray(String[]::new);
	}

	String prepareShellCommandForItem(String command, int selectedItem) {
		return stream(prepareCommandForItem(command, selectedItem)).map(OpenerLauncher::quoteForPosixShell).collect(joining(" "));
	}

	static String quoteForPosixShell(String value) {
		return "'" + value.replace("'", "'\"'\"'") + "'";
	}

	/**
	 * Splits the command provided as String into an array of parameters
	 * to be passed to the OS.
	 * This implementation supports quoting.
	 */
	static String[] splitCommand(String command) {
		List<String> result = new ArrayList<>();
		var token = new StringBuilder();
		char quote = 0;
		var quotePosition = -1;
		for (var i = 0; i < command.length(); i++) {
			var character = command.charAt(i);
			if (quote != 0) {
				if (character == quote) quote = 0;
				else token.append(character);
			}
			else if (character == '\'' || character == '"') {
				quote = character;
				quotePosition = token.length();
			}
			else if (Character.isWhitespace(character)) {
				if (!token.isEmpty()) {
					result.add(token.toString());
					token.setLength(0);
				}
			}
			else token.append(character);
		}
		if (quote != 0) token.insert(quotePosition, quote);
		if (!token.isEmpty()) result.add(token.toString());
		return result.toArray(String[]::new);
	}

	/**
	 * Replaces references to scanned values in an opener string.
	 * References look like ${fetcher_id}
	 * @param openerString
	 * @return opener string with values replaced
	 */
	String prepareOpenerStringForItem(String openerString, int selectedItem) {
		return prepareOpenerStringForItem(openerString, selectedItem, Function.identity());
	}

	private String prepareOpenerStringForItem(String openerString, int selectedItem, Function<String, String> replacementTransform) {
		var paramsPattern = Pattern.compile("\\$\\{(.+?)\\}");
		var matcher = paramsPattern.matcher(openerString);
		var sb = new StringBuilder(64);
		while (matcher.find()) {
			// resolve the required fetcher
			var fetcherId = matcher.group(1);

			// retrieve the scanned value
			var scannedValue = getScannedValue(selectedItem, fetcherId);
			if (scannedValue == null || scannedValue instanceof Empty) {
				throw new UserErrorException("opener.nullFetcherValue", fetcherId);					
			}
			
			matcher.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(replacementTransform.apply(scannedValue.toString())));
		}
		matcher.appendTail(sb);
		return sb.toString();
	}

	private Object getScannedValue(int selectedItem, String fetcherId) {
		var fetcherIndex = fetcherRegistry.getSelectedFetcherIndex(fetcherId);
		if (fetcherIndex < 0) {
			throw new UserErrorException("opener.unknownFetcher", fetcherId);
		}

		var value = scanningResults.getResult(selectedItem).getValues().get(fetcherIndex);
		
		if ((value == null || value instanceof Empty) && fetcherId.equals(HostnameFetcher.ID)) {
			// small innocent hardcode:
			// if we request a hostname, but get null, use the IP
			value = scanningResults.getResult(selectedItem).getAddress().getHostAddress();
		}
		
		return value;
	}
}
