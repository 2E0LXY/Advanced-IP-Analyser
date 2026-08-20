package net.azib.ipscan.gui.actions;

import net.azib.ipscan.core.UserErrorException;
import net.azib.ipscan.core.devices.SavedDevice;

/** Launches the most useful discovered service for a saved device. */
public class SavedDeviceLauncher {
    public void launch(SavedDevice device) {
        var action = preferredAction(device);
        try {
            if (action.startsWith("https://") || action.startsWith("http://") || action.startsWith("smb://") || action.startsWith("ftp://"))
                BrowserLauncher.openURL(action);
            else if (action.equals("rdp"))
                new ProcessBuilder("xfreerdp3", "/v:" + device.ipAddress()).start();
            else if (action.equals("ssh"))
                new ProcessBuilder("x-terminal-emulator", "-e", "ssh", device.ipAddress()).start();
            else throw new UserErrorException("devices.noService");
        }
        catch (UserErrorException e) {
            throw e;
        }
        catch (Exception e) {
            throw new UserErrorException("opener.failed", action);
        }
    }

    static String preferredAction(SavedDevice device) {
        var services = device.services();
        if (services.contains("https")) return "https://" + device.ipAddress() + '/';
        if (services.contains("http")) return "http://" + device.ipAddress() + '/';
        if (services.contains("smb")) return "smb://" + device.ipAddress() + '/';
        if (services.contains("rdp")) return "rdp";
        if (services.contains("ssh")) return "ssh";
        if (services.contains("ftp")) return "ftp://" + device.ipAddress() + '/';
        return "";
    }
}
