package org.tb.hiemdall;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan("org.tb.hiemdall")
public class HiemdallApplication {

    public static void main(String[] args) {
        SpringApplication.run(HiemdallApplication.class, args);
    }
}
