package net.zevrant.services.security.common.secrets.management.config;

import liquibase.integration.spring.SpringLiquibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Arrays;

import static java.lang.String.format;

@Profile("liquibase")
@Configuration
public class LiquibaseConfig {

    private static final Logger logger = LoggerFactory.getLogger(LiquibaseConfig.class);

    private final ConfigurableApplicationContext applicationContext;
    private final String prodChangeLogPath;
    private final String developChangeLogPath;
    private final String localChangeLogPath;

    @Autowired
    public LiquibaseConfig(ConfigurableApplicationContext applicationContext,
                           @Value("${zevrant.liquibase.changelog.path.local:classpath:db/changelog/db.changelog-master.yaml}")
                                   String localChangeLogPath,
                           @Value("${zevrant.liquibase.changelog.path.develop:classpath:db/changelog/db.changelog-master.yaml}")
                                   String developChangeLogPath,
                           @Value("${zevrant.liquibase.changelog.path.prod:classpath:db/changelog/db.changelog-master.yaml}")
                                   String prodChangeLogPath
    ) {
        this.applicationContext = applicationContext;
        this.localChangeLogPath = localChangeLogPath;
        this.developChangeLogPath = developChangeLogPath;
        this.prodChangeLogPath = prodChangeLogPath;
    }

    @Bean
    public SpringLiquibase liquibase(DataSource dataSource) {
        removeDBLock(dataSource);
        SpringLiquibase liquibase = new SpringLiquibase();
        liquibase.setDataSource(dataSource);
        String[] profiles = applicationContext.getEnvironment().getActiveProfiles();
        if (Arrays.asList(profiles).contains("develop")) {
            liquibase.setChangeLog(developChangeLogPath);
        } else if (Arrays.asList(profiles).contains("local")) {
            liquibase.setChangeLog(localChangeLogPath);
        } else {
            liquibase.setChangeLog(prodChangeLogPath);
        }
        return liquibase;
    }


    private void removeDBLock(DataSource dataSource) {

        //Timestamp, currently set to 3 mins or older.

        final Timestamp lastDBLockTime = new Timestamp(System.currentTimeMillis() - (3 * 60 * 1000));

        logger.debug(lastDBLockTime.toString());


        final String checkQuery = "select * from public.databasechangeloglock d";

        final String query = format("DELETE FROM DATABASECHANGELOGLOCK WHERE LOCKED=true AND LOCKGRANTED<'%s'", lastDBLockTime);


        try (Statement stmt = dataSource.getConnection().createStatement()) {
            ResultSet resultSet = stmt.executeQuery(checkQuery);

            boolean tableExists = resultSet.next(); //should throw exception on error, or return false is there is no locks
            if (tableExists) {
                try {
                    int updateCount = stmt.executeUpdate(query);
                    if (updateCount > 0) {
                        logger.info("Locks Removed Count: {} .", updateCount);
                    }
                } catch (SQLException e) {
                    logger.error("Error! Remove Change Lock threw and Exception. ", e);
                    System.exit(1);
                }
            }
        } catch (SQLException e) {
            logger.info("Table DatabaseChangelogLock not found.");
        }
    }
}
