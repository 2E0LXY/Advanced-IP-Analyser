/*
  This file is a part of Angry IP Scanner source code,
  see http://www.angryip.org/ for more information.
  Licensed under GPLv2.
 */

package net.azib.ipscan.fetchers;

import net.azib.ipscan.core.ScanningSubject;

import java.time.Instant;

/**
 * LastAliveTimeFetcher
 *
 * @author Anton Keks
 */
public class LastAliveTimeFetcher extends AbstractFetcher {
	public static final String ID = "fetcher.lastAlive";

	public String getId() {
		return ID;
	}

	public Object scan(ScanningSubject subject) {
		return subject.getResultType().ordinal() > net.azib.ipscan.core.ScanningResult.ResultType.DEAD.ordinal()
			? Instant.now().toString() : null;
	}

}
