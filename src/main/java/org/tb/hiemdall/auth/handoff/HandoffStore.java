package org.tb.hiemdall.auth.handoff;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * In-memory cache of Google-token bundles parked between the browser callback and the owning app's
 * back-channel exchange call.
 *
 * <p>Keys are random 32-byte values rendered as URL-safe base64 (no padding) — passed to the
 * browser as the {@code ?handoff=…} query param. {@link #consume} is atomic get-and-remove so
 * replays return null.
 */
@Component
public class HandoffStore {

    private static final Logger log = LoggerFactory.getLogger(HandoffStore.class);
    private static final int CODE_BYTES = 32;

    private final ConcurrentHashMap<String, HandoffEntry> entries = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private final HandoffProperties props;
    private final Clock clock;

    public HandoffStore(HandoffProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
    }

    /**
     * Parks a token bundle under a fresh opaque code and returns the code. Throws {@link
     * HandoffStoreFullException} when at capacity so callers can surface 503.
     */
    public String put(String appId, OAuthTokenResponse tokens, IdentityClaims identity) {
        if (entries.size() >= props.maxEntries()) {
            // Attempt a sweep inline — expired entries holding slots can push us past the cap on
            // their own. If we're still full afterward, surrender.
            sweep();
            if (entries.size() >= props.maxEntries()) {
                throw new HandoffStoreFullException(
                        "handoff store at capacity (" + props.maxEntries() + ")");
            }
        }
        String code = newCode();
        Instant expiresAt = Instant.now(clock).plus(props.ttl());
        entries.put(code, new HandoffEntry(appId, tokens, identity, expiresAt));
        return code;
    }

    /**
     * Atomically removes and returns the entry for {@code code}, iff it exists, has not expired,
     * and belongs to {@code appId}. Returns null in every other case so callers can collapse all
     * failure modes to a single 404.
     */
    public HandoffEntry consume(String appId, String code) {
        if (code == null || code.isBlank() || appId == null || appId.isBlank()) {
            return null;
        }
        HandoffEntry entry = entries.remove(code);
        if (entry == null) {
            return null;
        }
        if (!entry.appId().equals(appId)) {
            // Wrong caller — don't resurrect the entry under its real owner either; a replay by the
            // correct owner would already have grabbed it legitimately.
            log.warn("handoff consume with mismatched appId");
            return null;
        }
        if (Instant.now(clock).isAfter(entry.expiresAt())) {
            return null;
        }
        return entry;
    }

    /** Drops expired entries. Called by {@link HandoffStoreSweeper} and inline when at capacity. */
    int sweep() {
        Instant now = Instant.now(clock);
        int dropped = 0;
        Iterator<Map.Entry<String, HandoffEntry>> it = entries.entrySet().iterator();
        while (it.hasNext()) {
            if (now.isAfter(it.next().getValue().expiresAt())) {
                it.remove();
                dropped++;
            }
        }
        return dropped;
    }

    /** Visible for tests. */
    int size() {
        return entries.size();
    }

    private String newCode() {
        byte[] buf = new byte[CODE_BYTES];
        random.nextBytes(buf);
        return encoder.encodeToString(buf);
    }
}
