package org.tb.hiemdall.spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.tb.hiemdall.security.security.InternalAuthFilter;

/**
 * Spring Security wiring.
 *
 * <p>Two boundaries:
 *
 * <ul>
 *   <li>{@code /auth/**}, {@code /api/actuator/**} — public
 *   <li>{@code /internal/**} — {@link InternalAuthFilter} enforces X-Internal-Auth header BEFORE
 *       the request reaches Spring's authorize step
 * </ul>
 *
 * <p>CSRF is disabled at the framework level — the OAuth flow uses per-request state cookies with
 * SameSite=Lax. Session JWT wiring was stripped for v1; identity-engine work will reintroduce it in
 * v2.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, InternalAuthFilter internalAuthFilter)
            throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        auth ->
                                auth.requestMatchers("/auth/**", "/api/actuator/**", "/internal/**")
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated())
                // Wire in the internal-auth filter BEFORE the standard security filter chain runs
                // its authorize step — anything past this filter has already been authenticated
                // at the service + user layer.
                .addFilterBefore(
                        internalAuthFilter,
                        org.springframework.security.web.access.intercept.AuthorizationFilter
                                .class);
        return http.build();
    }
}
