package org.tb.hiemdall.auth.handoff;

/**
 * Thrown by {@link HandoffStore#put} when the cache is at {@code maxEntries}. Service layer maps
 * this to HTTP 503 — the auth attempt should fail loudly rather than silently drop tokens.
 */
public class HandoffStoreFullException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public HandoffStoreFullException(String message) {
        super(message);
    }
}
