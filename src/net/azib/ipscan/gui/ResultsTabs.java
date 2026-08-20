package net.azib.ipscan.gui;

import net.azib.ipscan.config.Labels;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.widgets.TabItem;

/** Hosts the live scan and persistent saved-device views. */
public class ResultsTabs extends TabFolder {
    public ResultsTabs(Shell parent) {
        super(parent, SWT.NONE);
    }

    public void addPage(String labelKey, Control control) {
        var item = new TabItem(this, SWT.NONE);
        item.setText(Labels.getLabel(labelKey));
        item.setControl(control);
    }

    @Override protected void checkSubclass() {}
}
