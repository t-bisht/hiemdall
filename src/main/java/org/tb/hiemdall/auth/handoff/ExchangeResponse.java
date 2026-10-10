package org.tb.hiemdall.auth.handoff;

import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * Response body for {@code POST /internal/auth/exchange}. Wraps the Google token bundle and the
 * verified identity claims so downstream apps get both halves of the login result in a single
 * payload.
 */
public record ExchangeResponse(OAuthTokenResponse tokens, IdentityClaims identity) {}
