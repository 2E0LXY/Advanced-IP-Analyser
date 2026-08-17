package net.azib.ipscan.util;

import org.eclipse.swt.SWTError;
import org.eclipse.swt.SWTException;

import java.util.logging.Logger;

import static java.util.logging.Level.FINE;

/**
 * Utility class to send statistics to Google Analytics (GA4).
 * https://developers.google.com/analytics/devguides/collection/protocol/ga4/sending-events?client_type=firebase
 */
public class GoogleAnalytics {
	public void report(String screen) {
		report("page_view", screen);
	}

	public void report(String type, String content) {
		// Advanced IP Analyser never sends telemetry or exception details over the network.
		Logger.getLogger(getClass().getName()).log(FINE, () -> "Telemetry disabled: " + type);
	}

	public void report(Throwable e) {
		report("exception", extractFirstStackFrame(e));
	}

	public void report(String message, Throwable e) {
		report("exception", message + "\n" + extractFirstStackFrame(e));
	}

	static String extractFirstStackFrame(Throwable e) {
		if (e == null) return "";
		var stackTrace = e.getStackTrace();
		StackTraceElement element = null;
		for (var stackTraceElement : stackTrace) {
			element = stackTraceElement;
			if (element.getClassName().startsWith("net.azib.ipscan")) break;
		}
		var code = e instanceof SWTError ? ((SWTError) e).code : e instanceof SWTException ? ((SWTException) e).code : -1;
		return e + (code >= 0 ? " (" + code + ")" : "") + (element == null ? "" : "\n" +
			   element.getClassName() + "." + element.getMethodName() + ":" + element.getLineNumber()) +
			   (e.getCause() != null ? ";\n" + extractFirstStackFrame(e.getCause()) : "");
	}

	public void asyncReport(final String screen) {
		new Thread(() -> report(screen)).start();
	}

	public static void main(String[] args) {
		new GoogleAnalytics().report("hello");
	}
}
