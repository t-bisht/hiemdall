package org.tb.hiemdall.auth.records;

/**
 * Provider-neutral identity fields extracted from an OIDC {@code id_token} payload (or, for
 * non-OIDC providers, from a userinfo response).
 *
 * <p>Fields map to OIDC Core §5.1 standard claims. Consumed by downstream user-engine upsert calls.
 */
public record IdentityClaims(String sub, String email, String name, String picture) {

    @Override
    public String toString() {
        return "IdentityClaims{"
                + "sub="
                + mask(sub)
                + ", email="
                + maskEmail(email)
                + ", name="
                + name
                + ", picture="
                + (picture == null ? "null" : "<present>")
                + '}';
    }

    private static String mask(String value) {
        if (value == null || value.isEmpty()) return "null";
        if (value.length() <= 4) return "****";
        return value.substring(0, 2) + "***" + value.substring(value.length() - 2);
    }

    private static String maskEmail(String email) {
        if (email == null || email.isEmpty()) return "null";
        int at = email.indexOf('@');
        if (at <= 1) return "****" + (at >= 0 ? email.substring(at) : "");
        return email.charAt(0) + "***" + email.substring(at);
    }
}
