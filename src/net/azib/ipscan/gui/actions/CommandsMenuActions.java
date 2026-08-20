/*
  This file is a part of Angry IP Scanner source code,
  see http://www.angryip.org/ for more information.
  Licensed under GPLv2.
 */
package net.azib.ipscan.gui.actions;

import net.azib.ipscan.config.Labels;
import net.azib.ipscan.config.OpenersConfig;
import net.azib.ipscan.core.UserErrorException;
import net.azib.ipscan.core.devices.DeviceInventory;
import net.azib.ipscan.core.devices.SavedDeviceFactory;
import net.azib.ipscan.core.net.WakeOnLan;
import net.azib.ipscan.core.remote.RemotePowerService;
import net.azib.ipscan.core.state.ScanningState;
import net.azib.ipscan.core.state.StateMachine;
import net.azib.ipscan.fetchers.FetcherRegistry;
import net.azib.ipscan.gui.DetailsWindow;
import net.azib.ipscan.gui.EditOpenersDialog;
import net.azib.ipscan.gui.FavoritesTable;
import net.azib.ipscan.gui.ResultTable;
import net.azib.ipscan.gui.StatusBar;
import org.eclipse.swt.SWT;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;

/**
 * Commands and Context menu Actions.
 * All these operate on the items, selected in the results list.
 *
 * @author Anton Keks
 */
public class CommandsMenuActions {
	public Details details;
	public Delete delete;
	public Rescan rescan;
	public CopyIP copyIP;
	public CopyIPDetails copyIPDetails;
	public WakeSelected wakeSelected;
	public SaveSelectedDevices saveSelectedDevices;
	public ShutdownSelected shutdownSelected;
	public RebootSelected rebootSelected;
	public CancelShutdownSelected cancelShutdownSelected;
	public ShowOpenersMenu showOpenersMenu;
	public EditOpeners editOpeners;
	public SelectOpener selectOpener;

	public CommandsMenuActions(Details details, Delete delete, Rescan rescan, CopyIP copyIP, CopyIPDetails copyIPDetails, WakeSelected wakeSelected, SaveSelectedDevices saveSelectedDevices, ShutdownSelected shutdownSelected, RebootSelected rebootSelected, CancelShutdownSelected cancelShutdownSelected, ShowOpenersMenu showOpenersMenu, EditOpeners editOpeners, SelectOpener selectOpener) {
		this.details = details;
		this.delete = delete;
		this.rescan = rescan;
		this.copyIP = copyIP;
		this.copyIPDetails = copyIPDetails;
		this.wakeSelected = wakeSelected;
		this.saveSelectedDevices = saveSelectedDevices;
		this.shutdownSelected = shutdownSelected;
		this.rebootSelected = rebootSelected;
		this.cancelShutdownSelected = cancelShutdownSelected;
		this.showOpenersMenu = showOpenersMenu;
		this.editOpeners = editOpeners;
		this.selectOpener = selectOpener;
	}

	private abstract static class RemotePowerAction implements Listener {
		private final ResultTable resultTable;
		private final RemotePowerService service;
		private final RemotePowerService.Action action;

		RemotePowerAction(ResultTable resultTable, RemotePowerService service, RemotePowerService.Action action) {
			this.resultTable = resultTable;
			this.service = service;
			this.action = action;
		}

		@Override public void handleEvent(Event event) {
			checkSelection(resultTable);
			var confirmation = new org.eclipse.swt.widgets.MessageBox(resultTable.getShell(), SWT.ICON_WARNING | SWT.YES | SWT.NO | SWT.SHEET);
			confirmation.setText(Labels.getLabel("remotePower.confirmTitle"));
			confirmation.setMessage(Labels.getLabel("remotePower.confirm"));
			if (confirmation.open() != SWT.YES) return;
			var hosts = java.util.Arrays.stream(resultTable.getSelectionIndices())
				.mapToObj(index -> resultTable.getScanningResults().getResult(index).getAddress().getHostAddress()).toList();
			var display = resultTable.getDisplay();
			var thread = new Thread(() -> {
				var outcomes = service.execute(hosts, action);
				display.asyncExec(() -> {
					if (resultTable.isDisposed()) return;
					var summary = new org.eclipse.swt.widgets.MessageBox(resultTable.getShell(), SWT.ICON_INFORMATION | SWT.OK | SWT.SHEET);
					summary.setText(Labels.getLabel("remotePower.results"));
					summary.setMessage(outcomes.stream().map(outcome -> outcome.host() + ": " + (outcome.successful() ? "OK" : "FAILED") + " — " + outcome.message()).collect(java.util.stream.Collectors.joining("\n")));
					summary.open();
				});
			}, "remote-power");
			thread.setDaemon(true);
			thread.start();
		}
	}

	public static final class ShutdownSelected extends RemotePowerAction {
		public ShutdownSelected(ResultTable table, RemotePowerService service) { super(table, service, RemotePowerService.Action.SHUTDOWN); }
	}
	public static final class RebootSelected extends RemotePowerAction {
		public RebootSelected(ResultTable table, RemotePowerService service) { super(table, service, RemotePowerService.Action.REBOOT); }
	}
	public static final class CancelShutdownSelected extends RemotePowerAction {
		public CancelShutdownSelected(ResultTable table, RemotePowerService service) { super(table, service, RemotePowerService.Action.CANCEL_SHUTDOWN); }
	}

	public static final class SaveSelectedDevices implements Listener {
		private final ResultTable resultTable;
		private final DeviceInventory inventory;
		private final FavoritesTable favoritesTable;

		public SaveSelectedDevices(ResultTable resultTable, DeviceInventory inventory, FavoritesTable favoritesTable) {
			this.resultTable = resultTable;
			this.inventory = inventory;
			this.favoritesTable = favoritesTable;
		}

		@Override public void handleEvent(Event event) {
			checkSelection(resultTable);
			var results = resultTable.getScanningResults();
			for (var index : resultTable.getSelectionIndices())
				inventory.save(SavedDeviceFactory.from(results.getResult(index), results.getFetchers()));
			favoritesTable.refresh();
		}
	}

	/** Sends Wake-on-LAN packets to all selected results that have a MAC address. */
	public static final class WakeSelected implements Listener {
		private final ResultTable resultTable;
		private final WakeOnLan wakeOnLan;

		public WakeSelected(ResultTable resultTable, WakeOnLan wakeOnLan) {
			this.resultTable = resultTable;
			this.wakeOnLan = wakeOnLan;
		}

		public void handleEvent(Event event) {
			checkSelection(resultTable);
			var woken = 0;
			for (var index : resultTable.getSelectionIndices()) {
				var mac = resultTable.getScanningResults().getResult(index).getMac();
				if (mac == null || mac.isBlank()) continue;
				try {
					wakeOnLan.wake(mac);
					woken++;
				}
				catch (Exception e) {
					throw new UserErrorException("wol.failed", e);
				}
			}
			if (woken == 0) throw new UserErrorException("wol.noMac");
		}
	}

	/**
	 * Checks that there is at least one item selected in the results list.
	 */
	static void checkSelection(ResultTable resultTable) {
		if (resultTable.getItemCount() <= 0) {
			throw new UserErrorException("commands.noResults");
		}
		else
		if (resultTable.getSelectionIndex() < 0) {
			throw new UserErrorException("commands.noSelection");
		}
	}

	public static class Details implements Listener {
		private final ResultTable resultTable;
		private final DetailsWindow detailsWindow;
		
		public Details(ResultTable resultTable, DetailsWindow detailsWindow) {
			this.resultTable = resultTable;
			this.detailsWindow = detailsWindow;
			resultTable.addListener(SWT.Traverse, this);
			resultTable.addListener(SWT.MouseDoubleClick, this);
		}

		public void handleEvent(Event event) {
			// activate only if something is selected
			if (event.type == SWT.Selection || (resultTable.getSelectionIndex() >= 0 && (event.type == SWT.MouseDoubleClick || event.detail == SWT.TRAVERSE_RETURN))) {
				event.doit = false;
				checkSelection(resultTable);
				detailsWindow.open(); 
			}
		}
	}
	
	public static final class Delete implements Listener {
		private final ResultTable resultTable;
		private final StateMachine stateMachine;

		public Delete(ResultTable resultTable, StateMachine stateMachine) {
			this.resultTable = resultTable;
			this.stateMachine = stateMachine;
		}

		public void handleEvent(Event event) {
			// ignore other keys if this is a KeyDown event - 
			// the same listener is used for several events
			if (event.type == SWT.KeyDown && event.keyCode != SWT.DEL) return;
			// deletion not allowed when scanning
			if (!stateMachine.inState(ScanningState.IDLE)) return;

			var firstSelection = resultTable.getSelectionIndex();
			if (firstSelection < 0) return;

			resultTable.remove(resultTable.getSelectionIndices());
			resultTable.setSelection(firstSelection);
			event.widget = resultTable;
			resultTable.notifyListeners(SWT.Selection, event);
		}
	}

	public static final class Rescan implements Listener {
		private final ResultTable resultTable;
		private final StateMachine stateMachine;

		public Rescan(ResultTable resultTable, StateMachine stateMachine) {
			this.resultTable = resultTable;
			this.stateMachine = stateMachine;
		}

		public void handleEvent(Event event) {
			checkSelection(resultTable);
			stateMachine.rescan();
		}
	}
	
	/**
	 * Copies currently selected IP to the clipboard.
	 * Used as both menu item listener and key down listener.
	 */
	public static final class CopyIP implements Listener {
		private final ResultTable resultTable;

		public CopyIP(ResultTable resultTable) {
			this.resultTable = resultTable;
		}

		public void handleEvent(Event event) {
			if (event.type == SWT.KeyDown) {
				// if this is not Ctrl+C or nothing is selected, then simply do nothing
				if (!isCopyShortcut(event) || resultTable.getSelectionIndex() < 0)
					return;
			}
			else {
				// if selected from the menu, check selection
				checkSelection(resultTable);
			}
			var clipboard = new Clipboard(event.display);
			clipboard.setContents(new Object[] {resultTable.getItem(resultTable.getSelectionIndex()).getText()}, new Transfer[] {TextTransfer.getInstance()});
			clipboard.dispose();
		}

		static boolean isCopyShortcut(Event event) {
			return (event.keyCode == 'c' || event.keyCode == 'C') && (event.stateMask & SWT.MOD1) != 0;
		}
	}
	
	public static final class CopyIPDetails implements Listener {
		private final ResultTable resultTable;

		public CopyIPDetails(ResultTable resultTable) {
			this.resultTable = resultTable;
		}

		public void handleEvent(Event event) {
			checkSelection(resultTable);
			var clipboard = new Clipboard(event.display);
			clipboard.setContents(new Object[] {resultTable.getSelectedResult().toString()}, new Transfer[] {TextTransfer.getInstance()});
			clipboard.dispose();
		}
	}
	
	public static final class ShowOpenersMenu implements Listener {
		
		private final Listener openersSelectListener;
		private final OpenersConfig openersConfig;
		private final ClientAvailability clientAvailability;

		public ShowOpenersMenu(OpenersConfig openersConfig, SelectOpener selectOpener, ClientAvailability clientAvailability) {
			this.openersConfig = openersConfig;
			this.openersSelectListener = selectOpener;
			this.clientAvailability = clientAvailability;
		}

		public void handleEvent(Event event) {
			var openersMenu = (Menu)event.widget;
			var menuItems = openersMenu.getItems();
			for (var i = 2; i < menuItems.length; i++) {
				menuItems[i].dispose();
			}
			
			// update menu items
			var index = 0;
			for (var configuredName : openersConfig) {
				var name = configuredName;
				var menuItem = new MenuItem(openersMenu, SWT.CASCADE);
				var available = clientAvailability.isAvailable(openersConfig.getOpener(configuredName));
				
				index++;
				if (index <= 9) {
					name += "\tCtrl+" + index;
					menuItem.setAccelerator(SWT.MOD1 | ('0' + index));
				}
				
				menuItem.setText(name + (available ? "" : " (not installed)"));
				menuItem.setEnabled(available);
				menuItem.setData(index);
				menuItem.addListener(SWT.Selection, openersSelectListener);
			}

		}
	}
		
	public static final class EditOpeners implements Listener {
		
		private final FetcherRegistry fetcherRegistry;
		private final OpenersConfig openersConfig;

		public EditOpeners(FetcherRegistry fetcherRegistry, OpenersConfig openersConfig) {
			this.fetcherRegistry = fetcherRegistry;
			this.openersConfig = openersConfig;
		}

		public void handleEvent(Event event) {
			new EditOpenersDialog(fetcherRegistry, openersConfig).open(); 
		}
	}
	
	public static final class SelectOpener implements Listener {
		
		private final StatusBar statusBar;
		private final ResultTable resultTable;
		private final OpenerLauncher openerLauncher;
		private final OpenersConfig openersConfig;

		public SelectOpener(OpenersConfig openersConfig, StatusBar statusBar, ResultTable resultTable, OpenerLauncher openerLauncher) {
			this.openersConfig = openersConfig;
			this.statusBar = statusBar;
			this.resultTable = resultTable;
			this.openerLauncher = openerLauncher;
		}
		
		public void handleEvent(Event event) {
			var menuItem = (MenuItem) event.widget;
			var name = menuItem.getText();
			var indexOf = name.lastIndexOf('\t');
			if (indexOf >= 0) {
				name = name.substring(0, indexOf);
			}
			var opener = openersConfig.getOpener(name);

			var selectionIndices = resultTable.getSelectionIndices();
			if (selectionIndices.length == 0)
				throw new UserErrorException("commands.noSelection");

			for (var i : selectionIndices) {
				try {
					statusBar.setStatusText(Labels.getLabel("state.opening") + name);
					openerLauncher.launch(opener, i);
					// wait a bit to make status visible
					Thread.sleep(100);
				}
				catch (InterruptedException ignore) {}
				finally {
					statusBar.setStatusText(null);
				}
			}
		}
	}
}
