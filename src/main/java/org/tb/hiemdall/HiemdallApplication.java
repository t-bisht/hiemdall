package org.tb.hiemdall;

import java.time.Clock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@ConfigurationPropertiesScan("org.tb.hiemdall")
@EnableScheduling
public class HiemdallApplication {

    public static void main(String[] args) {
        SpringApplication.run(HiemdallApplication.class, args);
    }

    /** Overridable in tests so time-sensitive code (handoff expiry) is deterministic. */
    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
