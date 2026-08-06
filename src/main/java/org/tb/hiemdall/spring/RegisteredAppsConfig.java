package org.tb.hiemdall.spring;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RegisteredAppsConfig {

    public record RegisteredApp(String appName, String postAuthRedirect) {}

    @Bean(name = "appRegister")
    public Map<String, RegisteredApp> registeredApps() {
        Map<String, RegisteredApp> appsRegister = new ConcurrentHashMap<>();
        appsRegister.put(
                "kkt", new RegisteredApp("KharchaKhata", "http://localhost:8082/dashboard"));

        return appsRegister;
    }
}
