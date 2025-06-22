eating bean with name 'liquibase' defined in class path resource [org/springframework/boot/autoconfigure/liquibase/LiquibaseAutoConfiguration$LiquibaseConfiguration.class]:
 liquibase.exception.CommandExecutionException: liquibase.exception.ChangeLogParseException: classpath:/db/changelog/db.changelog-master.yaml does not exist
2025-06-22T05:20:06.346+01:00  INFO 25260 --- [           main] com.zaxxer.hikari.HikariDataSource       : HikariPool-2 - Shutdown initiated...
2025-06-22T05:20:06.352+01:00  INFO 25260 --- [           main] com.zaxxer.hikari.HikariDataSource       : HikariPool-2 - Shutdown completed.
2025-06-22T05:20:06.353+01:00  INFO 25260 --- [           main] o.apache.catalina.core.StandardService   : Stopping service [Tomcat]
2025-06-22T05:20:06.404+01:00  INFO 25260 --- [           main] .s.b.a.l.ConditionEvaluationReportLogger :

Error starting ApplicationContext. To display the condition evaluation report re-run your application with 'debug' enabled.
2025-06-22T05:20:06.576+01:00 ERROR 25260 --- [           main] o.s.b.d.LoggingFailureAnalysisReporter   :

***************************
APPLICATION FAILED TO START
***************************

Description:

Liquibase failed to start because no changelog could be found at 'classpath:/db/changelog/db.changelog-master.yaml'.

Action:

Make sure a Liquibase changelog is present at the configured path.

[ERROR] Tests run: 1, Failures: 0, Errors: 1, Skipped: 0, Time elapsed: 45.633 s <<< FAILURE! - in com.rbs.bdd.application.service.EspSimulatorEngineTest
[ERROR] testMainMethodCoverage  Time elapsed: 10.851 s  <<< ERROR!
org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'entityManagerFactory' defined in class path resource [org/springframework/boot/autoc
onfigure/orm/jpa/HibernateJpaConfiguration.class]: Failed to initialize dependency 'liquibase' of LoadTimeWeaverAware bean 'entityManagerFactory': Error creating bean with
name 'liquibase' defined in class path resource [org/springframework/boot/autoconfigure/liquibase/LiquibaseAutoConfiguration$LiquibaseConfiguration.class]: liquibase.except
ion.CommandExecutionException: liquibase.exception.ChangeLogParseException: classpath:/db/changelog/db.changelog-master.yaml does not exist
        at com.rbs.bdd.application.service.EspSimulatorEngineTest.testMainMethodCoverage(EspSimulatorEngineTest.java:19)
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'liquibase' defined in class path resource [org/springframework/boot/autoc
onfigure/liquibase/LiquibaseAutoConfiguration$LiquibaseConfiguration.class]: liquibase.exception.CommandExecutionException: liquibase.exception.ChangeLogParseException: cla
sspath:/db/changelog/db.changelog-master.yaml does not exist
        at com.rbs.bdd.application.service.EspSimulatorEngineTest.testMainMethodCoverage(EspSimulatorEngineTest.java:19)
Caused by: liquibase.exception.UnexpectedLiquibaseException: liquibase.exception.CommandExecutionException: liquibase.exception.ChangeLogParseException: classpath:/db/chang
elog/db.changelog-master.yaml does not exist
        at com.rbs.bdd.application.service.EspSimulatorEngineTest.testMainMethodCoverage(EspSimulatorEngineTest.java:19)
Caused by: liquibase.exception.CommandExecutionException: liquibase.exception.ChangeLogParseException: classpath:/db/changelog/db.changelog-master.yaml does not exist
        at com.rbs.bdd.application.service.EspSimulatorEngineTest.testMainMethodCoverage(EspSimulatorEngineTest.java:19)
Caused by: liquibase.exception.ChangeLogParseException: classpath:/db/changelog/db.changelog-master.yaml does not exist
        at com.rbs.bdd.application.service.EspSimulatorEngineTest.testMainMethodCoverage(EspSimulatorEngineTest.java:19)

2025-06-22T05:20:06.748+01:00  INFO 25260 --- [ionShutdownHook] j.LocalContainerEntityManagerFactoryBean : Closing JPA EntityManagerFactory for persistence unit 'default'
2025-06-22T05:20:06.759+01:00  INFO 25260 --- [ionShutdownHook] com.zaxxer.hikari.HikariDataSource       : HikariPool-1 - Shutdown initiated...
2025-06-22T05:20:06.764+01:00  INFO 25260 --- [ionShutdownHook] com.zaxxer.hikari.HikariDataSource       : HikariPool-1 - Shutdown completed.
[INFO]
[INFO] Results:
[INFO]
[ERROR] Errors:
