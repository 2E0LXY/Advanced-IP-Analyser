package net.azib.ipscan.gui;

import net.azib.ipscan.config.Labels;
import net.azib.ipscan.core.devices.DeviceInventory;
import net.azib.ipscan.core.devices.SavedDevice;
import net.azib.ipscan.gui.actions.SavedDeviceLauncher;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Table view of the durable device inventory. */
public class FavoritesTable extends Table {
    private final DeviceInventory inventory;

    public FavoritesTable(ResultsTabs parent, DeviceInventory inventory, SavedDeviceLauncher launcher) {
        super(parent, SWT.BORDER | SWT.MULTI | SWT.FULL_SELECTION);
        this.inventory = inventory;
        setHeaderVisible(true);
        setLinesVisible(true);
        addColumn(Labels.getLabel("devices.name"), 180);
        addColumn(Labels.getLabel("devices.ip"), 130);
        addColumn(Labels.getLabel("devices.mac"), 145);
        addColumn(Labels.getLabel("devices.comment"), 190);
        addColumn(Labels.getLabel("devices.lastSeen"), 190);
        addColumn(Labels.getLabel("devices.services"), 180);
        parent.addPage("tabs.favorites", this);
		parent.addListener(SWT.Selection, event -> {
			if (parent.getSelection().length > 0 && parent.getSelection()[0].getControl() == this) refresh();
		});
        createContextMenu();
        refresh();
		addListener(SWT.MouseDoubleClick, event -> {
			var selected = selectedDevices();
			if (!selected.isEmpty()) launcher.launch(selected.getFirst());
		});
    }

    public void refresh() {
        removeAll();
        for (var device : inventory.all()) {
            var item = new TableItem(this, SWT.NONE);
            item.setData(device);
            item.setText(new String[] {device.name(), device.ipAddress(), device.macAddress(), device.comment(),
                device.lastSeenEpochMillis() == 0 ? "" : Instant.ofEpochMilli(device.lastSeenEpochMillis()).toString(),
                String.join(", ", device.services())});
			item.setBackground(getDisplay().getSystemColor(getItemCount() % 2 == 0 ? SWT.COLOR_LIST_BACKGROUND : SWT.COLOR_WIDGET_LIGHT_SHADOW));
        }
    }

    public List<SavedDevice> selectedDevices() {
        var selected = new ArrayList<SavedDevice>();
        for (var item : getSelection()) selected.add((SavedDevice) item.getData());
        return List.copyOf(selected);
    }

    private void addColumn(String name, int width) {
        var column = new TableColumn(this, SWT.NONE);
        column.setText(name);
        column.setWidth(width);
    }

    private void createContextMenu() {
        var menu = new Menu(this);
        var remove = new MenuItem(menu, SWT.PUSH);
        remove.setText(Labels.getLabel("devices.remove"));
        remove.addListener(SWT.Selection, event -> {
            for (var device : selectedDevices()) inventory.remove(device.identity());
            refresh();
        });
        new MenuItem(menu, SWT.SEPARATOR);
        var importItem = new MenuItem(menu, SWT.PUSH);
        importItem.setText(Labels.getLabel("devices.import"));
        importItem.addListener(SWT.Selection, event -> {
            var dialog = new FileDialog(getShell(), SWT.OPEN);
            dialog.setFilterExtensions(new String[] {"*.xml"});
            var selected = dialog.open();
            if (selected != null) {
                inventory.importXml(java.nio.file.Path.of(selected));
                refresh();
            }
        });
        var exportItem = new MenuItem(menu, SWT.PUSH);
        exportItem.setText(Labels.getLabel("devices.export"));
        exportItem.addListener(SWT.Selection, event -> exportDevices());
        setMenu(menu);
    }

    private void exportDevices() {
        var dialog = new FileDialog(getShell(), SWT.SAVE);
        dialog.setFilterNames(new String[] {"XML inventory", "CSV", "HTML"});
        dialog.setFilterExtensions(new String[] {"*.xml", "*.csv", "*.html"});
        var destination = dialog.open();
        if (destination == null) return;
        var values = selectedDevices();
        if (values.isEmpty()) values = inventory.all();
        var path = java.nio.file.Path.of(destination);
        var lower = destination.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith(".csv")) inventory.exportCsv(path, values);
        else if (lower.endsWith(".html") || lower.endsWith(".htm")) inventory.exportHtml(path, values);
        else inventory.exportXml(path, values);
    }

    @Override protected void checkSubclass() {}
}
