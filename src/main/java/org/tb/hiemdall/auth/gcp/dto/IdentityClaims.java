package org.tb.hiemdall.auth.gcp.dto;

import org.tb.hiemdall.auth.gcp.IdTokenClaimsReader;
import org.tb.hiemdall.security.SessionJwtIssuer;

/**
 * Identity fields extracted from a Google {@code id_token} payload.
 *
 * <p>Constructed by {@link IdTokenClaimsReader}. Consumed by {@link SessionJwtIssuer} when minting
 * session JWTs, and (later) by the {@code user_engine} upsert call.
 *
 * <p>Values are trusted because the {@code id_token} arrives back-channel from Google over TLS —
 * see spec Open Q #15 on skipping signature verification.
 */
public record IdentityClaims(String sub, String email, String name, String picture) {}
