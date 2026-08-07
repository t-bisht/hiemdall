package org.tb.hiemdall.spring;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

/**
 * Registry of downstream apps allowed to initiate auth through hiemdall. Bound to {@code
 * app.registered-apps.*}. Defaults live in {@code application.yml}; production values are supplied
 * via an external file merged in through {@code SPRING_CONFIG_IMPORT} (see {@code
 * docker-compose.yml} and {@code .env.example}).
 */
@Validated
@Configuration
@ConfigurationProperties(prefix = "app")
public class RegisteredAppsConfig {

    private Map<String, @Valid RegisteredApp> registeredApps = new ConcurrentHashMap<>();

    public Map<String, RegisteredApp> getRegisteredApps() {
        return registeredApps;
    }

    public void setRegisteredApps(Map<String, RegisteredApp> registeredApps) {
        this.registeredApps = registeredApps;
    }

    @Bean(name = "appRegister")
    public Map<String, RegisteredApp> appRegister() {
        return registeredApps;
    }

    public record RegisteredApp(@NotBlank String appName, @NotBlank String postAuthRedirect) {}
}
