/*
  This file is a part of Angry IP Scanner source code,
  see http://www.angryip.org/ for more information.
  Licensed under GPLv2.
 */
package net.azib.ipscan.core.net;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.LinkedHashSet;

/** Sends the standard Wake-on-LAN magic packet for a discovered MAC address. */
public class WakeOnLan {
	static final int DEFAULT_PORT = 9;

	public void wake(String macAddress) throws IOException {
		var payload = createMagicPacket(macAddress);
		var broadcasts = new LinkedHashSet<InetAddress>();
		var interfaces = NetworkInterface.networkInterfaces();
		for (var networkInterface : interfaces.toList()) {
			if (!networkInterface.isUp() || networkInterface.isLoopback()) continue;
			for (var interfaceAddress : networkInterface.getInterfaceAddresses()) {
				if (interfaceAddress.getBroadcast() != null)
					broadcasts.add(interfaceAddress.getBroadcast());
			}
		}
		if (broadcasts.isEmpty()) broadcasts.add(InetAddress.getByName("255.255.255.255"));

		try (var socket = new DatagramSocket()) {
			socket.setBroadcast(true);
			for (var broadcast : broadcasts)
				socket.send(new DatagramPacket(payload, payload.length, broadcast, DEFAULT_PORT));
		}
	}

	/** Creates six 0xff bytes followed by sixteen repetitions of the MAC. */
	public static byte[] createMagicPacket(String macAddress) {
		if (macAddress == null)
			throw new IllegalArgumentException("MAC address is required");

		if (!macAddress.matches("(?i)(?:[0-9a-f]{2}[:-]?){5}[0-9a-f]{2}"))
			throw new IllegalArgumentException("Invalid MAC address: " + macAddress);
		var normalized = macAddress.replace(":", "").replace("-", "");

		var mac = new byte[6];
		try {
			for (var i = 0; i < mac.length; i++)
				mac[i] = (byte) Integer.parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid MAC address: " + macAddress, e);
		}

		var packet = new byte[6 + 16 * mac.length];
		for (var i = 0; i < 6; i++) packet[i] = (byte) 0xff;
		for (var i = 6; i < packet.length; i += mac.length)
			System.arraycopy(mac, 0, packet, i, mac.length);
		return packet;
	}
}
