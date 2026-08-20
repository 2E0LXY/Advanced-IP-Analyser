package net.azib.ipscan.core.devices;

import net.azib.ipscan.core.UserErrorException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

/** Persistent, versioned inventory of saved devices. */
public class DeviceInventory {
    private static final String FORMAT_VERSION = "1";
    private final Path storageFile;
    private final LinkedHashMap<String, SavedDevice> devices = new LinkedHashMap<>();

    public DeviceInventory() {
        this(Path.of(System.getProperty("user.home"), ".advanced-ip-analyser", "devices.xml"));
    }

    DeviceInventory(Path storageFile) {
        this.storageFile = storageFile;
        if (Files.isRegularFile(storageFile)) importXml(storageFile, false);
    }

    public synchronized List<SavedDevice> all() {
        return List.copyOf(devices.values());
    }

    public synchronized boolean contains(String identity) {
        return devices.containsKey(identity);
    }

    public synchronized SavedDevice save(SavedDevice device) {
		var saved = mergeIntoInventory(device);
        persist();
        return saved;
    }

    public synchronized void saveAll(Collection<SavedDevice> values) {
        for (var value : values) mergeIntoInventory(value);
        persist();
    }

    public synchronized boolean remove(String identity) {
        if (devices.remove(identity) == null) return false;
        persist();
        return true;
    }

    private SavedDevice mergeIntoInventory(SavedDevice device) {
        if (!device.macAddress().isEmpty()) {
            var fallback = devices.remove("ip:" + device.ipAddress().toLowerCase(java.util.Locale.ROOT));
            if (fallback != null) device = fallback.adoptMacIdentity(device);
        }
        return devices.merge(device.identity(), device, SavedDevice::merge);
    }

    public synchronized int importXml(Path source) {
        return importXml(source, true);
    }

    private int importXml(Path source, boolean persistAfterImport) {
        try {
            var document = secureDocumentBuilderFactory().newDocumentBuilder().parse(source.toFile());
            var root = document.getDocumentElement();
            if (!"advanced-ip-analyser-devices".equals(root.getTagName()) || !FORMAT_VERSION.equals(root.getAttribute("version")))
                throw new IllegalArgumentException("Unsupported device inventory format");
            var imported = 0;
            var nodes = root.getElementsByTagName("device");
            for (var i = 0; i < nodes.getLength(); i++) {
                var element = (Element) nodes.item(i);
                var services = new ArrayList<String>();
                var serviceNodes = element.getElementsByTagName("service");
                for (var j = 0; j < serviceNodes.getLength(); j++) services.add(serviceNodes.item(j).getTextContent());
                var device = new SavedDevice(
                    element.getAttribute("name"), element.getAttribute("ip"), element.getAttribute("mac"),
                    textOf(element, "comment"), parseLastSeen(element.getAttribute("last-seen")), services);
				mergeIntoInventory(device);
                imported++;
            }
            if (persistAfterImport) persist();
            return imported;
        }
        catch (Exception e) {
            throw new UserErrorException("devices.importFailed", e);
        }
    }

    public synchronized void exportXml(Path destination, Collection<SavedDevice> selected) {
        writeXml(destination, selected);
    }

    public synchronized void exportCsv(Path destination, Collection<SavedDevice> selected) {
        try (var writer = Files.newBufferedWriter(destination, StandardCharsets.UTF_8)) {
            writer.write("Name,IP Address,MAC Address,Comment,Last Seen,Services\n");
            for (var device : selected) {
                writer.write(csv(device.name()) + ',' + csv(device.ipAddress()) + ',' + csv(device.macAddress()) + ',' +
                    csv(device.comment()) + ',' + csv(lastSeen(device)) + ',' + csv(String.join(";", device.services())) + "\n");
            }
        }
        catch (IOException e) {
            throw new UserErrorException("devices.exportFailed", e);
        }
    }

    public synchronized void exportHtml(Path destination, Collection<SavedDevice> selected) {
        try (BufferedWriter writer = Files.newBufferedWriter(destination, StandardCharsets.UTF_8)) {
            writer.write("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Advanced IP Analyser devices</title>");
            writer.write("<table><thead><tr><th>Name</th><th>IP Address</th><th>MAC Address</th><th>Comment</th><th>Last Seen</th><th>Services</th></tr></thead><tbody>");
            for (var device : selected) writer.write("<tr><td>" + html(device.name()) + "</td><td>" + html(device.ipAddress()) +
                "</td><td>" + html(device.macAddress()) + "</td><td>" + html(device.comment()) + "</td><td>" + html(lastSeen(device)) +
                "</td><td>" + html(String.join(", ", device.services())) + "</td></tr>");
            writer.write("</tbody></table></html>");
        }
        catch (IOException e) {
            throw new UserErrorException("devices.exportFailed", e);
        }
    }

    private void persist() {
        writeXml(storageFile, devices.values());
    }

    private void writeXml(Path destination, Collection<SavedDevice> selected) {
        try {
            var parent = destination.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            var document = secureDocumentBuilderFactory().newDocumentBuilder().newDocument();
            var root = document.createElement("advanced-ip-analyser-devices");
            root.setAttribute("version", FORMAT_VERSION);
            document.appendChild(root);
            for (var device : selected) appendDevice(document, root, device);
            var temporary = destination.resolveSibling(destination.getFileName() + ".tmp");
            var transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            var transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(document), new StreamResult(temporary.toFile()));
            try {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            }
            catch (IOException atomicMoveUnavailable) {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        catch (Exception e) {
            throw new UserErrorException("devices.exportFailed", e);
        }
    }

    private static void appendDevice(Document document, Element root, SavedDevice device) {
        var element = document.createElement("device");
        element.setAttribute("name", device.name());
        element.setAttribute("ip", device.ipAddress());
        element.setAttribute("mac", device.macAddress());
        element.setAttribute("last-seen", Long.toString(device.lastSeenEpochMillis()));
        var comment = document.createElement("comment");
        comment.setTextContent(device.comment());
        element.appendChild(comment);
        var services = document.createElement("services");
        for (var value : device.services()) {
            var service = document.createElement("service");
            service.setTextContent(value);
            services.appendChild(service);
        }
        element.appendChild(services);
        root.appendChild(element);
    }

    private static DocumentBuilderFactory secureDocumentBuilderFactory() throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    private static String textOf(Element parent, String tag) {
        var nodes = parent.getElementsByTagName(tag);
        return nodes.getLength() == 0 ? "" : nodes.item(0).getTextContent();
    }

    private static long parseLastSeen(String value) {
        try { return Long.parseLong(value); }
        catch (NumberFormatException e) { return 0; }
    }

    private static String lastSeen(SavedDevice device) {
        return device.lastSeenEpochMillis() == 0 ? "" : Instant.ofEpochMilli(device.lastSeenEpochMillis()).toString();
    }

    private static String csv(String value) {
        return '"' + value.replace("\"", "\"\"") + '"';
    }

    private static String html(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
