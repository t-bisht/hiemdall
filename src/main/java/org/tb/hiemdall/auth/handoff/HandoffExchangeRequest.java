package org.tb.hiemdall.auth.handoff;

import jakarta.validation.constraints.NotBlank;

/**
 * Request body for {@code POST /internal/auth/exchange}. The owning app's backend sends the opaque
 * handoff code the browser landed with, plus its own appId as a sanity check.
 */
public record HandoffExchangeRequest(@NotBlank String app, @NotBlank String handoff) {}
