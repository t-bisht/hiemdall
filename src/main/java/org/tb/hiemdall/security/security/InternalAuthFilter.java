package org.tb.hiemdall.security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.tb.hiemdall.auth.exception.InternalAuthInvalidException;
import org.tb.hiemdall.auth.exception.InternalAuthMissingException;
import org.tb.hiemdall.security.config.InternalAuthProperties;

/**
 * Filter for the {@code /internal/**} boundary. Requires {@code X-Internal-Auth} header to equal
 * the shared secret in {@link InternalAuthProperties#svcToken()} (constant-time compare).
 */
@Component
public class InternalAuthFilter extends OncePerRequestFilter {

    public static final String INTERNAL_AUTH_HEADER = "X-Internal-Auth";

    private final InternalAuthProperties props;

    public InternalAuthFilter(InternalAuthProperties props) {
        this.props = props;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String svcHeader = request.getHeader(INTERNAL_AUTH_HEADER);
        if (svcHeader == null || svcHeader.isBlank()) {
            throw new InternalAuthMissingException("X-Internal-Auth header missing");
        }
        if (!MessageDigest.isEqual(
                svcHeader.getBytes(StandardCharsets.UTF_8),
                props.svcToken().getBytes(StandardCharsets.UTF_8))) {
            throw new InternalAuthInvalidException("X-Internal-Auth does not match");
        }

        chain.doFilter(request, response);
    }
}
