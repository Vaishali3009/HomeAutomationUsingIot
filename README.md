package com.rbs.bdd.application.service;

import com.rbs.bdd.EspSimulatorEngine;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Unit test to invoke the main method in {@link EspSimulatorEngine}
 * and increase code coverage.
 */
@ActiveProfiles("test")
@SpringBootTest
class EspSimulatorEngineTest {

    @Test
    void testMainMethodCoverage() {
        // Simulate running the application
        EspSimulatorEngine.main(new String[] {});
    }
}


------------------
application-test.properties


secret.manager.enabled=false
spring.liquibase.enabled=false

# H2 Database
spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
spring.datasource.driver-class-name=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=

