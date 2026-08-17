package net.azib.ipscan.gui.actions;

import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Event;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CommandsMenuActionsTest {
	@Test
	public void recognizesOnlyCopyShortcut() {
		var event = new Event();
		event.keyCode = 'c';
		event.stateMask = SWT.MOD1;
		assertTrue(CommandsMenuActions.CopyIP.isCopyShortcut(event));

		event.keyCode = 'x';
		assertFalse(CommandsMenuActions.CopyIP.isCopyShortcut(event));

		event.keyCode = 'c';
		event.stateMask = 0;
		assertFalse(CommandsMenuActions.CopyIP.isCopyShortcut(event));
	}
}
