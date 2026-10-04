package org.tb.hiemdall.auth.handoff;

import java.time.Instant;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * One parked Google-token bundle waiting for an app's backend to redeem it via {@code
 * /internal/auth/exchange}.
 *
 * <p>Entries are keyed by an opaque code (see {@link HandoffStore}); {@code appId} is captured here
 * so a consume with a mismatched app returns null — stops app A from redeeming app B's code even if
 * it somehow learned the string.
 */
public record HandoffEntry(
        String appId, OAuthTokenResponse tokens, IdentityClaims identity, Instant expiresAt) {}
