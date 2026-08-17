package net.azib.ipscan.core.net;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class WakeOnLanTest {
	@Test
	public void createsMagicPacketFromCommonMacFormats() {
		var packet = WakeOnLan.createMagicPacket("01:23:45:67:89:ab");
		assertEquals(102, packet.length);
		assertArrayEquals(new byte[] {-1, -1, -1, -1, -1, -1}, slice(packet, 0, 6));
		for (var offset = 6; offset < packet.length; offset += 6)
			assertArrayEquals(new byte[] {1, 35, 69, 103, -119, -85}, slice(packet, offset, offset + 6));

		assertArrayEquals(packet, WakeOnLan.createMagicPacket("01-23-45-67-89-AB"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsMalformedMacAddress() {
		WakeOnLan.createMagicPacket("not-a-mac");
	}

	private static byte[] slice(byte[] bytes, int from, int to) {
		var result = new byte[to - from];
		System.arraycopy(bytes, from, result, 0, result.length);
		return result;
	}
}
