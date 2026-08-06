package org.tb.hiemdall.auth.records;

/**
 * Provider-neutral identity fields extracted from an OIDC {@code id_token} payload (or, for
 * non-OIDC providers, from a userinfo response).
 *
 * <p>Fields map to OIDC Core §5.1 standard claims. Consumed by {@code SessionJwtIssuer} when
 * minting session JWTs and by downstream user-engine upsert calls.
 */
public record IdentityClaims(String sub, String email, String name, String picture) {}
