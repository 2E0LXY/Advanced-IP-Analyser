package net.azib.ipscan.core.devices;

import net.azib.ipscan.core.ScanningResultList;
import net.azib.ipscan.core.state.ScanningState;
import net.azib.ipscan.core.state.StateMachine;
import net.azib.ipscan.core.state.StateTransitionListener;

/** Refreshes already-saved devices after every completed scan. */
public class DeviceInventoryUpdater implements StateTransitionListener {
    private final DeviceInventory inventory;
    private final ScanningResultList results;

    public DeviceInventoryUpdater(DeviceInventory inventory, ScanningResultList results, StateMachine stateMachine) {
        this.inventory = inventory;
        this.results = results;
        stateMachine.addTransitionListener(this);
    }

    @Override public void transitionTo(ScanningState state, StateMachine.Transition transition) {
        if (state != ScanningState.IDLE || transition != StateMachine.Transition.COMPLETE) return;
        for (var result : results) {
            var candidate = SavedDeviceFactory.from(result, results.getFetchers());
            if (inventory.contains(candidate.identity()) || inventory.contains("ip:" + candidate.ipAddress().toLowerCase(java.util.Locale.ROOT)))
                inventory.save(candidate);
        }
    }
}
