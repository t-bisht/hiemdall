package org.tb.hiemdall.auth.handoff;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Periodic janitor that drops expired entries from {@link HandoffStore}. Cadence driven by {@code
 * app.handoff.sweep-every}. The store itself also sweeps opportunistically on {@code put} when at
 * capacity, so this is a safety net rather than the primary cleanup path.
 */
@Component
public class HandoffStoreSweeper {

    private static final Logger log = LoggerFactory.getLogger(HandoffStoreSweeper.class);

    private final HandoffStore store;

    public HandoffStoreSweeper(HandoffStore store) {
        this.store = store;
    }

    @Scheduled(fixedDelayString = "${app.handoff.sweep-every}")
    public void sweep() {
        int dropped = store.sweep();
        if (dropped > 0) {
            log.debug("handoff sweeper dropped {} expired entries", dropped);
        }
    }
}
