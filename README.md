
In the SIT ENv :-

1. For Account Validation :-
https://bdd-ms-esp-simulation-service.dcp.sit.euw1.shared.banksvcs.net/ws/ArrValidationForPaymentParameters.wsdl
https://bdd-ms-esp-simulation-service.dcp.sit.euw1.shared.banksvcs.net/ws/ArrValidationForPaymentParameters


2.
1. For Customor Retrieval :-
https://bdd-ms-esp-simulation-service.dcp.sit.euw1.shared.banksvcs.net/ws/CustomerRetrievalForPayment.wsdl
https://bdd-ms-esp-simulation-service.dcp.sit.euw1.shared.banksvcs.net/ws/CustomerRetrievalForPayment



3. Local

   http://localhost:8080/ws/ArrValidationForPaymentParameters.wsdl
   http://localhost:8080/ws/CustomerRetrievalForPayment.wsdl



package com.rbs.bdd.application.awsconfig;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

@Slf4j
@Configuration
public class AwsSecretManagerConfig {

    @Bean
    @ConditionalOnProperty(name = "secret.manager.enabled", havingValue = "true")
    public SecretsManagerClient secretsManagerClient(@Value("${aws.region}") String region,
                                                     @Value("${secret.datasource.name}") String secretDatasourceName) {
        log.info("AWS-AWS_REGION {}", region);
        SecretsManagerClient client = SecretsManagerClient.builder()
                .region(Region.of(region))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
        log.info("Verify access");
        log.info("Secret DatasourceName "+secretDatasourceName);

        GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId(secretDatasourceName)
                .build();

        log.info("Trying to establish"+secretDatasourceName);

        try {
            log.error("Request"+request);
            GetSecretValueResponse response = client.getSecretValue(request);
            log.error("Trying to establish");
            if (response.sdkHttpResponse().isSuccessful()) {
                log.info("aws secret retrieved [{}] successfully [{}]", secretDatasourceName,
                        response.secretString());
            }
        } catch (Exception u) {
            log.error("Unable to get the secret", u);
        }
        return client;
    }
}



-------------------------
package com.rbs.bdd.application.awsconfig;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rbs.bdd.application.exception.SecretsNotFoundException;
import com.zaxxer.hikari.HikariDataSource;
import liquibase.integration.spring.SpringLiquibase;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Configuration
@ConditionalOnProperty(name = "secret.manager.enabled", havingValue = "true")

public class DatabaseConfig {
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${spring.datasource.base.url}")
    private String springDatasourceBaseUrl;

    @Value("${spring.datasource.username}")
    private String springDatasourceUsername;

    @Value("${spring.datasource.password}")
    private String springDatasourcePassword;

    @Value("${spring.liquibase.default-schema}")
    private String springLiquibaseDefaultSchema;

    @Value("${secret.datasource.name}")
    private String secretDatasourceName;

    @Autowired(required = false)
    private SecretsManagerClient secretsManagerClient;


    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String DBNAME = "dbname";

    //Fetch kubernetes secrets from the aws server
    private Map<String, String> fetchSecrets(final SecretsManagerClient secretsManagerClient, final String secretName) {

        log.debug("Request received to retrieve secrets for  : {}", secretName);
        Map<String, String> secretMap = new HashMap<>();
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(secretName).build();

        GetSecretValueResponse response = secretsManagerClient.getSecretValue(request);
        if (response.sdkHttpResponse().isSuccessful()) {
            log.info("Secret retrieved for [{}] ", secretName);
            try {
                secretMap = mapper.readValue(response.secretString(), Map.class);
                log.info("SecretMap: Username: {}", secretMap.get(USERNAME));
            } catch (Exception e) {
                log.error("unable to retrieve data from secret");
                throw new SecretsNotFoundException("Unable to retrieve data from secrets!");
            }
        }
        return secretMap;
    }

    @ConfigurationProperties(prefix = "spring.datasource")
    @ConditionalOnProperty(prefix = "spring.liquibase", name = "enabled", havingValue = "true")

    @Bean
    public DataSourceProperties dataSourceProperties() {
        return new DataSourceProperties();
    }

    @Primary
    @ConditionalOnProperty(prefix = "spring.liquibase", name = "enabled", havingValue = "true")
    @Bean
    public DataSource dataSource() {
        Map<String, String> secrets = fetchSecrets(secretsManagerClient, secretDatasourceName);
        HikariDataSource hikariDataSource = new HikariDataSource();
        log.debug("Using aws secretDatasource : {} and  secretsManagerClient: {}", secretDatasourceName, secretsManagerClient);

        hikariDataSource.setJdbcUrl(springDatasourceBaseUrl + secrets.get(DBNAME));
        log.debug("Connecting to Datasource : {} ", hikariDataSource.getJdbcUrl());
        log.debug("Secrets are available for user : {} ", secrets.get(USERNAME));

        hikariDataSource.setUsername(secrets.get(USERNAME));
        hikariDataSource.setPassword(secrets.get(PASSWORD));
        return hikariDataSource;
    }

    @ConditionalOnProperty(prefix = "spring.liquibase", name = "enabled", havingValue = "true")
    @Bean

    public SpringLiquibase SpringLiquibase() {
        SpringLiquibase springLiquibase=null;
        try {
            Map<String, String> secrets = fetchSecrets(secretsManagerClient, secretDatasourceName);
             springLiquibase = new SpringLiquibase();
            springLiquibase.setDataSource(dataSource());
            log.info("DBNAME :" + DBNAME);
            log.info("secretsManagerClient : " + secretsManagerClient);
            log.info("secretDatasourceName :" + secretDatasourceName);
            springLiquibase.setDefaultSchema(secrets.get(DBNAME));
            log.info("Default Scehma :" + springLiquibase.getDefaultSchema());

            springLiquibase.setChangeLog("classpath:/db/changelog/db.changelog-master.yaml");
            springLiquibase.setContexts("");
            return springLiquibase;
        }
        catch(Exception ex)
        {
            log.error("error occured : "+ex);
        }
        return springLiquibase;
    }

}



--------------------
package com.rbs.bdd.application.port.in;

import org.springframework.ws.WebServiceMessage;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;

/**
 * Entry port for handling SOAP requests related to customer retrieval.
 * Follows hexagonal architecture's `port in` pattern.
 */
public interface CustomerRetrievalPort {
        /**
         * Validates a customer retrieval request by delegating to the underlying orchestrator/service.
         *
         * @param request The SOAP request payload.
         * @param message The outgoing WebServiceMessage to be modified and returned.
         */
        void validateCustomerRetrieval(RetrievePrimaryCustomerForArrRequest request, WebServiceMessage message);


    }



---------------------
package com.rbs.bdd.application.port.in;


import org.springframework.ws.WebServiceMessage;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;
/**
 * Entry port for handling SOAP requests related to payment validation.
 * Follows hexagonal architecture's `port in` pattern.
 */
public interface PaymentValidationPort {


    /**
     * Validates a payment arrangement request by delegating to the underlying orchestrator/service.
     *
     * @param request The SOAP request payload.
     * @param message The outgoing WebServiceMessage to be modified and returned.
     */
    void validateArrangementForPayment(ValidateArrangementForPaymentRequest request,WebServiceMessage message);



}



--------------------
package com.rbs.bdd.application.port.out;

import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;

import org.springframework.ws.WebServiceMessage;

/**
 * Defines the business contract for validating payment accounts.
 * Used by the orchestrator to call schema and business rule validators.
 */
public interface AccountValidationPort {
    /**
     * Performs XSD schema validation of the request. (Currently delegated to Spring WS config.)
     *
     * @param request The SOAP request payload.
     */
    void validateSchema(ValidateArrangementForPaymentRequest request);


    /**
     * Applies business rules on the static response XML based on request content,
     * and writes the final SOAP response directly to the output message.
     *
     * @param request The incoming SOAP request.
     * @param message The WebServiceMessage to write the modified response to.
     */
    void validateBusinessRules(ValidateArrangementForPaymentRequest request,WebServiceMessage message);

     }



------------------
package com.rbs.bdd.application.port.out;



import org.springframework.ws.WebServiceMessage;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;


/**
 * Defines the business contract for validating customer  accounts.
 * Used by the orchestrator to call schema and business rule validators.
 */
public interface RetrieveCustomerPort {
    /**
     * Performs XSD schema validation of the request. (Currently delegated to Spring WS config.)
     *
     * @param request The SOAP request payload.
     */
    void validateSchema(RetrievePrimaryCustomerForArrRequest request);


    /**
     * Applies business rules on the  response XML based on request content,
     * and writes the final SOAP response directly to the output message.
     *
     * @param request The incoming SOAP request.
     * @param message The WebServiceMessage to write the modified response to.
     */
    void retrieveCustomer(RetrievePrimaryCustomerForArrRequest request, WebServiceMessage message);

}



-----------------
package com.rbs.bdd.application.service;

import com.rbs.bdd.application.port.out.AccountValidationPort;
import com.rbs.bdd.application.port.in.PaymentValidationPort;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.ws.WebServiceMessage;

/**
 * Service class responsible for orchestrating the validation flow of payment arrangement requests.
 * Implements {@link PaymentValidationPort} and delegates schema and business rule validation
 * to the appropriate output port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AccountValidationOrchestrator implements PaymentValidationPort {

    private final AccountValidationPort accountValidationPort;




    /**
     * Entry point for handling the SOAP request. Validates schema and applies business rules.
     *
     * @param request the incoming SOAP request payload
     * @param message the SOAP WebServiceMessage used to write the final response
     */
    @Override
    public void validateArrangementForPayment(ValidateArrangementForPaymentRequest request,WebServiceMessage message) {
        log.info("Account Validation Orchestrator Service is called for account validation");
        accountValidationPort.validateSchema(request); // automatic validation through interceptors
        accountValidationPort.validateBusinessRules(request,message);
    }

}

-----------------------
package com.rbs.bdd.application.service;


import com.rbs.bdd.application.exception.AccountValidationException;
import com.rbs.bdd.application.port.out.AccountValidationPort;
import com.rbs.bdd.domain.enums.*;
import com.rbs.bdd.domain.model.ErrorDetail;
import com.rbs.bdd.util.ValidationUtils;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;

import jakarta.xml.soap.SOAPException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import com.rbs.bdd.util.ValidationUtils.RequestParams;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;


import static com.rbs.bdd.domain.enums.AccountStatus.DOMESTIC_RESTRICTED;
import static com.rbs.bdd.domain.enums.AccountStatus.DOMESTIC_UNRESTRICTED;
import static com.rbs.bdd.domain.enums.ModulusCheckStatus.FAILED;
import static com.rbs.bdd.domain.enums.ModulusCheckStatus.PASSED;
import static com.rbs.bdd.domain.enums.ServiceConstants.AccountTypes.INTL_BANK_ACCOUNT;
import static com.rbs.bdd.domain.enums.ServiceConstants.IBANs.*;
import static com.rbs.bdd.domain.enums.SwitchingStatus.NOT_SWITCHING;
import static com.rbs.bdd.domain.enums.SwitchingStatus.SWITCHED;
import static com.rbs.bdd.util.ValidationUtils.generateTxnId;
import static com.rbs.bdd.util.ValidationUtils.writeResponseToSoapMessage;

/**
 * Service responsible for validating SOAP requests for account validation and returning
 * static success or error responses based on configured rules.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountValidationService implements AccountValidationPort {


    /**
     * Logs the fact that schema validation is already handled by Spring WS.
     */
    @Override
    public void validateSchema(ValidateArrangementForPaymentRequest request) {
        log.info("Schema validation completed by Spring WS");
    }



    /**
     * Applies business rule validation based on account identifiers, code values, and IBAN/UBAN checks.
     * Depending on the logic, either a static success or error response is returned.
     *
     * @param request the incoming SOAP request
     * @param message the SOAP response message to be modified
     */
    @Override
    public void validateBusinessRules(ValidateArrangementForPaymentRequest request, WebServiceMessage message) {
        try {
            log.info("Starting business rule validation for request.");
            RequestParams params = extractParams(request);
            XPath xpath = XPathFactory.newInstance().newXPath();
            Document responseDoc = handleBusinessValidation(params, xpath);

            writeResponseToSoapMessage(message,responseDoc);
            log.info("Response sent Successfully");

        } catch (Exception ex) {
            log.error("Business rule validation failed", ex);
            throw new AccountValidationException("Validation failed", ex);
        }
    }



    private Document handleBusinessValidation(RequestParams params, XPath xpath) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException { log.debug("Checking for the error in the request");

        Optional<ErrorDetail> error = determineError(params);
        if (error.isPresent()) {
            return buildErrorResponse(error.get(), params.originalTxnId(), xpath);
        }

        Optional<ResponseConfig> config = determineMatchingConfig(params);
        if (config.isPresent()) {
            return buildSuccessResponse(params, config.get(), xpath);
        }

        return buildErrorResponse(ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId(), xpath);
    }
    private Document buildErrorResponse(ErrorDetail detail, String txnId, XPath xpath)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
        Document errorDoc = loadAndParseXml(ServiceConstants.Paths.ACCOUNT_VALIDATION_ERROR_XML);
        applyErrorResponse(errorDoc, xpath, detail, txnId);
        return errorDoc;
    }

    private Document buildSuccessResponse(RequestParams params, ResponseConfig config, XPath xpath)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
        Document successDoc = loadAndParseXml("static-response/account-validation/success-response.xml");

        if (INTL_BANK_ACCOUNT.equals(params.codeValue()) && config.bankIdentifier() == null) {
            return buildErrorResponse(ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId(), xpath);
        }

        updateSuccessResponse(successDoc, xpath, config, params);
        return successDoc;
    }

    private String resolveBankIdentifier(String iban) {
       Map<String, String> BANK_CODES = Map.of(
                "NWB", "278",
                "RBS", "365",
                "UBN", "391"
        );
        if (iban == null || iban.isEmpty()) return null;
        return BANK_CODES.entrySet()
                .stream()
                .filter(entry -> iban.contains(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }


    /**
     * Extracts key fields like identifier, codeValue, transactionId, and systemId from the SOAP request.
     */
    private RequestParams extractParams(ValidateArrangementForPaymentRequest request) {
        String identifier = request.getArrangementIdentifier().getIdentifier();
        String codeValue = request.getArrangementIdentifier().getContext().getCodeValue();
        String txnId = request.getRequestHeader().getRequestIds().get(0).getTransactionId();
        String systemId = request.getRequestHeader().getRequestIds().get(0).getSystemId();
        log.debug("Extracted request parameters: identifier={}, codeValue={}, txnId={}, systemId={}",
                identifier, codeValue, txnId, systemId);
        return new RequestParams(identifier, codeValue, txnId, systemId);
    }

    /**
     * Validates error conditions such as invalid IBAN/UBAN format or mismatched values.
     */
    private Optional<ErrorDetail> determineError(RequestParams p) {
        Map<ValidationErrorType, ErrorDetail> errorMap = Map.of(
                ValidationErrorType.INVALID_PREFIX, ErrorConstants.ERR_DB2_SQL.detail(),
                ValidationErrorType.INVALID_IBAN_LENGTH, ErrorConstants.ERR_INVALID_IBAN_LENGTH.detail(),
                ValidationErrorType.INVALID_UBAN_LENGTH, ErrorConstants.ERR_INVALID_UBAN_LENGTH.detail(),
                ValidationErrorType.INVALID_MODULUS, ErrorConstants.ERR_MOD97_UBAN.detail(),
                ValidationErrorType.INVALID_COUNTRY_CODE , ErrorConstants.ERR_WRONG_COUNTRY_CODE.detail()
        );

        return ValidationUtils.validateAccount(p, errorMap, this::isUbanValid, "AccountValidation");
    }

    /**
     * Matches the request against known account types and configurations.
     */
    private Optional<ResponseConfig> determineMatchingConfig(RequestParams p) {
    log.info("Entering in determineMatchingConfig "+p.identifier());
        log.info("Entering in determineMatchingConfig "+p.codeValue());
        String bankIdentifier = INTL_BANK_ACCOUNT.equals(p.codeValue()) ? resolveBankIdentifier(p.identifier()) : null;

        Map<String, ResponseConfig> ruleMap = Map.of(
        IBAN_1, new ResponseConfig(DOMESTIC_RESTRICTED, SWITCHED, PASSED,bankIdentifier),
        IBAN_2, new ResponseConfig(DOMESTIC_RESTRICTED, NOT_SWITCHING, PASSED,bankIdentifier),
        IBAN_3, new ResponseConfig(DOMESTIC_UNRESTRICTED, SWITCHED, PASSED,bankIdentifier),
        IBAN_4, new ResponseConfig(DOMESTIC_UNRESTRICTED, NOT_SWITCHING, FAILED,bankIdentifier)

    );

    return ruleMap.entrySet().stream()
        .filter(e -> isMatch(p, e.getKey()))
        .findFirst()
        .map(Map.Entry::getValue)
        .map(Optional::of)
        .orElse(Optional.empty());

    }

    /**
     * Checks if the request identifier matches exactly or by suffix.
     */
    private boolean isMatch(RequestParams p, String account) {
        return p.identifier().equals(account) || extractLast14Digits(account).equals(p.identifier());
    }

    /**
     * Verifies if the given UBAN matches the suffix of known IBANs.
     */
    private boolean isUbanValid(String identifier) {
        return ServiceConstants.IBANs.ALL_IBANS.stream()
                .map(this::extractLast14Digits)
                .anyMatch(ibanSuffix -> ibanSuffix.equals(identifier));
    }

    /**
     * Extracts last 14 digits from a given IBAN string.
     */
    private String extractLast14Digits(String iban) {
        return iban.length() >= 14 ? iban.substring(iban.length() - 14) : "";
    }

    /**
     * Reads and parses a static XML file from the classpath.
     */
    private Document loadAndParseXml(String path) throws ParserConfigurationException, IOException, SAXException {
        log.debug("Loading XML from path: {}", path);
        InputStream xml = getClass().getClassLoader().getResourceAsStream(path);
        if (Objects.isNull(xml)) {
            log.error("XML file not found at path: {}", path);
            throw new AccountValidationException("XML not found: " + path);
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(xml);
    }

    /**
     * Populates values in the success response based on matched config.
     */
    private void updateSuccessResponse(Document doc, XPath xpath, ResponseConfig config, RequestParams p) throws XPathExpressionException {
        log.info("Started Updating the response XML with success values");
        updateText(xpath, doc, "//responseId/systemId", p.systemId());
        updateText(xpath, doc, "//responseId/transactionId", generateTxnId());
        updateText(xpath, doc, "//status", config.accountStatus.getValue());
        updateText(xpath, doc, "//switchingStatus", config.switchingStatus.getValue());
        updateText(xpath, doc, "//modulusCheckStatus/codeValue", config.modulusCheckStatus.getValue());
        if(config.bankIdentifier()!=null)
        {
            updateText(xpath, doc, "//parentOrganization/alternativeIdentifier/identifier",config.bankIdentifier());

        }
        log.info("Updated response XML with success values");
    }

    /**
     * Populates values in the static error response XML.
     */
    private void applyErrorResponse(Document doc, XPath xpath, ErrorDetail errorDetail, String txnId) throws XPathExpressionException {
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_RESPONSE_ID_TXN_ID, generateTxnId());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_REF_REQUEST_TXN_ID, txnId);
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_CMD_STATUS, "Failed");
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_CMD_DESCRIPTION, errorDetail.description());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_TIMESTAMP, ZonedDateTime.now().toString());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_RETURN_CODE, errorDetail.returnCode());
        if (Objects.nonNull(errorDetail.systemNotificationDesc())) {

            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC, errorDetail.systemNotificationDesc());
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_CODE, errorDetail.systemNotificationCode());
        } else {

            Node node = (Node) xpath.evaluate(ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_BLOCK, doc, XPathConstants.NODE);
            if (node != null && node.getParentNode() != null) {
                node.getParentNode().removeChild(node);
                log.debug("Removed systemNotification block as it was not applicable.");
            }
        }
        log.info("Updated response XML with error values: {}", errorDetail.description());
    }

    /**
     * Utility method to update a specific XML node’s text content.
     */
    private void updateText(XPath xpath, Document doc, String path, String value) throws XPathExpressionException {
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null && value != null) {
            node.setTextContent(value);
            log.debug("Updated XML node {} with value {}", path, value);
        }
    }



    /**
     * Immutable container representing a valid account configuration.
     * this record is left without methods or additional logic,as it is only
     * used to group and transport validation results such as
     * <ul>
     *     <li>{@code accountStatus} - the classification of the account(eg , restricted,unrestricted)</li>
     *      <li>{@code switchingStatus} - whether the account has been switched or not switching </li>
     *       <li>{@code modulusStatus} - result of modulus check </li>
     *       <li>{@code bankIdentifier} - result of bankIdentifier </li>
     * </ul>
     */
     @SuppressWarnings("unused")
    public record ResponseConfig(AccountStatus accountStatus, SwitchingStatus switchingStatus,ModulusCheckStatus modulusCheckStatus,String bankIdentifier ) {
     // this record is left without methods or additional logic,as it is only used to group and transport validation results
     }



}


--------------------
package com.rbs.bdd.application.service;

import com.rbs.bdd.application.port.in.CustomerRetrievalPort;
import com.rbs.bdd.application.port.in.PaymentValidationPort;
import com.rbs.bdd.application.port.out.AccountValidationPort;
import com.rbs.bdd.application.port.out.RetrieveCustomerPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.ws.WebServiceMessage;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;



/**
 * Service class responsible for orchestrating the validation flow of Customer Retrieval requests.
 * Implements {@link CustomerRetrievalPort} and delegates schema and business rule validation
 * to the appropriate output port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomerRetrievalOrchestrator implements CustomerRetrievalPort {

    private final RetrieveCustomerPort retrieveCustomerPort;


    /**
     * Entry point for handling the SOAP request. Validates schema and applies business rules.
     *
     * @param request the incoming SOAP request payload
     * @param message the SOAP WebServiceMessage used to write the final response
     */
    @Override
    public void validateCustomerRetrieval(RetrievePrimaryCustomerForArrRequest request, WebServiceMessage message) {
        log.info("Customer Retrieval Orchestrator Service is called for customer Retrieval");
        retrieveCustomerPort.validateSchema(request); // automatic validation through interceptors
        retrieveCustomerPort.retrieveCustomer(request, message);
    }

}


-------------------
package com.rbs.bdd.application.service;




import com.rbs.bdd.application.exception.AccountValidationException;
import com.rbs.bdd.application.exception.CustomerRetrievalException;
import com.rbs.bdd.application.port.out.RetrieveCustomerPort;
import com.rbs.bdd.domain.enums.CustomerNameMapping;
import com.rbs.bdd.domain.enums.ErrorConstants;
import com.rbs.bdd.domain.enums.ServiceConstants;
import com.rbs.bdd.domain.enums.ValidationErrorType;
import com.rbs.bdd.domain.model.ErrorDetail;
import com.rbs.bdd.infrastructure.entity.CustomerData;
import com.rbs.bdd.infrastructure.repository.CustomerRepository;
import com.rbs.bdd.util.ValidationUtils.RequestParams;
import com.rbs.bdd.util.ValidationUtils;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.ws.WebServiceMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.rbs.bdd.domain.enums.ServiceConstants.XPath.*;
import static com.rbs.bdd.util.ValidationUtils.generateTxnId;
import static com.rbs.bdd.util.ValidationUtils.writeResponseToSoapMessage;

/**
 * Service to handle logic for retrieving customer details based on account number.
 * Matches specific identifiers and dynamically updates SOAP XML response.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomerRetrievalService implements RetrieveCustomerPort {

    private final CustomerRepository repository;

    private static final Logger logger = LoggerFactory.getLogger(CustomerRetrievalService.class);
    private static final String STATIC_RESPONSE_PATH = "static-response/customer-retrieval/success-response.xml";

    @Override
    public void validateSchema(RetrievePrimaryCustomerForArrRequest request) {
        logger.info("Schema validated successfully by Spring WS.");
    }

    @Override
    public void retrieveCustomer(RetrievePrimaryCustomerForArrRequest request, WebServiceMessage message) {
        try {
            RequestParams params = extractParams(request);
            XPath xpath = XPathFactory.newInstance().newXPath();
            Document responseDoc = handleCustomerRetrieval(params, xpath);

            writeResponseToSoapMessage(message, responseDoc);
        } catch (Exception e) {
            logger.error("Customer retrieval failed", e);
            throw new CustomerRetrievalException("Customer retrieval failed", e);
        }
    }


    private Document handleCustomerRetrieval(RequestParams params, XPath xpath) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
        logger.debug("Handle Customer Retrieval");
        Optional<ErrorDetail> error = determineCustomerRetrievalError(params);
        if (error.isPresent()) {
            return buildErrorResponse(error.get(), xpath, params.originalTxnId(),
                    ServiceConstants.Paths.ERROR_XML_PATH_FOR_CUSTOMER_RETRIEVAL);}
        // 1. Try DB match
        Optional<CustomerData> dbResult = repository.findByAccountNo(params.identifier());
        if (dbResult.isPresent() && dbResult.get().getAccountType().equals(params.codeValue())) {
            logger.info("Account matched in DB for IBAN: {}", params.identifier());
            CustomerInfo customer = new CustomerInfo(dbResult.get().getPrefixType(),
                    dbResult.get().getFirstName(),
                    dbResult.get().getLastName());
            return buildSuccessResponse(xpath, customer);}
        // 2. Try hardcoded account match
        CustomerNameMapping matched = CustomerNameMapping.fromIdentifier(params.identifier());
        if (matched != null) {
            logger.info("Account matched in config list for IBAN: {}", params.identifier());
            CustomerInfo customer = new CustomerInfo(
                    matched.getPrefixType(),
                    matched.getFirstName(),
                    matched.getLastName());
            return buildSuccessResponse(xpath, customer);}
        // 3. Nothing matched
        logger.error("Customer Not Found for IBAN: {}", params.identifier());
        return buildErrorResponse(ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail(), xpath, params.originalTxnId(),
                ServiceConstants.Paths.ACCOUNT_VALIDATION_ERROR_XML);}

    private Document buildSuccessResponse(XPath xpath, CustomerInfo customer) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

        Document responseDoc = loadAndParseXml(STATIC_RESPONSE_PATH);
        updateName(responseDoc, xpath, customer);
        return responseDoc;
    }

    private Document buildErrorResponse(ErrorDetail errorDetail, XPath xpath, String txnId, String errorXmlPath) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

        Document errorDoc = loadAndParseXml(errorXmlPath);
        applyErrorResponse(errorDoc, xpath, errorDetail, txnId);
        return errorDoc;
    }






    private void updateName(Document doc, XPath xpath, CustomerInfo customerData) throws XPathExpressionException {
        updateText(xpath, doc, XPATH_PREFIX_TYPE, customerData.prefixType());
        updateText(xpath, doc, XPATH_FIRST_NAME, customerData.firstName);
        updateText(xpath, doc, XPATH_LAST_NAME, customerData.lastName());
    }

    private Optional<ErrorDetail> determineCustomerRetrievalError(RequestParams param) {

        Map<ValidationErrorType, ErrorDetail> errorMap = Map.of(
                ValidationErrorType.INVALID_PREFIX, ErrorConstants.ERR_UBAN_GB.detail(),
                ValidationErrorType.INVALID_LENGTH, ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail(),
                ValidationErrorType.INVALID_MODULUS, ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail()
        );

        return ValidationUtils.validateAccount(param, errorMap, this::isUbanValid, "CustomerRetrieval");
    }

    /**
     * Verifies if the given UBAN matches the suffix of known IBANs.
     */
    private boolean isUbanValid(String identifier) {
        return ServiceConstants.IBANs.ALL_IBANS.stream()
                .map(this::extractLast14Digits)
                .anyMatch(ibanSuffix -> ibanSuffix.equals(identifier));
    }

    /**
     * Extracts last 14 digits from a given IBAN string.
     */
    private String extractLast14Digits(String iban) {
        log.debug("Entered in extractLast14Digits ");
        return iban.length() >= 14 ? iban.substring(iban.length() - 14) : "";
    }
    private void applyErrorResponse(Document doc, XPath xpath, ErrorDetail detail, String txnId) throws XPathExpressionException {
        log.debug("Entered in applyErrorResponse");
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_RESPONSE_ID_TXN_ID, generateTxnId());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_REF_REQUEST_TXN_ID, txnId);
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_CMD_STATUS, "Failed");
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_CMD_DESCRIPTION, detail.description());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_TIMESTAMP, ZonedDateTime.now().toString());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_RETURN_CODE, detail.returnCode());

        if ("Customer Not Found".equals(detail.systemNotificationDesc())){
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC, detail.systemNotificationDesc());
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_CODE, detail.systemNotificationCode());
        } else {
            Node node = (Node) xpath.evaluate(ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_BLOCK, doc, XPathConstants.NODE);
            if (Objects.nonNull(node) && Objects.nonNull(node.getParentNode())) {
                node.getParentNode().removeChild(node);
            }
        }
    }

    private void
    updateText(XPath xpath, Document doc, String path, String value) throws XPathExpressionException {
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null && value != null) node.setTextContent(value);
    }

    private Document loadAndParseXml(String path) throws ParserConfigurationException, IOException, SAXException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream(path);
        if (Objects.isNull(stream)) {
            log.error("XML file not found at path: {}", path);
            throw new AccountValidationException("XML not found: " + path);
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(stream);
    }

    private RequestParams extractParams(RetrievePrimaryCustomerForArrRequest request) {
        logger.debug("Extract Params from request ");
        return new RequestParams(
                request.getArrangementIdentifier().getIdentifier(),
                request.getArrangementIdentifier().getContext().getCodeValue(),
                request.getRequestHeader().getRequestIds().get(0).getTransactionId(),
                request.getRequestHeader().getRequestIds().get(0).getSystemId()
        );
    }
    /**
     * Immutable container representing a valid request configuration.
     * this record is left without methods or additional logic,as it is only
     *  used to group and transport request fields such as
     *  <ul>
     *     <li>{@code identifier} - contains account number </li>
     *     <li>{@code codeValue} - used to identify
     * whether account is UKBasicBankAccountNumber or InternationalBankAccountNumber</li>
     *      <li>{@code originalTxnId} - return the transactionId of the request </li>
     *       <li>{@code systemId} - returns the systemId from the request </li>
     *       </ul>
     */
    @SuppressWarnings("unused")
    public record CustomerInfo(String prefixType, String firstName, String lastName) {
        // this record is left without methods or additional logic,as it is only used to group and transport request fields

    }
   }


   ----------------

package com.rbs.bdd.application.exception;



/**
 * Exception thrown when  the account validation fails during SOAP request processing.
 */
public class AccountValidationException extends RuntimeException {

    /**
     * Constructs a new AccountValidationException with a specific message.
     *
     * @param message the detail message
     */
    public AccountValidationException(String message) {
        super(message);
    }

    /**
     * Constructs a new AccountValidationException with a message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public AccountValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}

-------------------
package com.rbs.bdd.application.exception;

/**
 * Exception thrown when  the customer Retrieval fails during SOAP request processing.
 */
public class CustomerRetrievalException extends RuntimeException {

    /**
     * Constructs a new CustomerRetrievalException with a specific message.
     *
     * @param message the detail message
     */
    public CustomerRetrievalException(String message) {
        super(message);
    }

    /**
     * Constructs a new CustomerRetrievalException with a message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public CustomerRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}



-----------------------
package com.rbs.bdd.application.exception;

/**
 * Exception thrown when  the schema validation fails during SOAP request processing.
 */
public class SchemaValidationException extends RuntimeException {

    /**
     * Constructs a new SchemaValidationException with a specific message.
     *
     * @param message the detail message
     */
    public SchemaValidationException(String message) {
        super(message);
    }

    /**
     * Constructs a new SchemaValidationException with a message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public SchemaValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}


------------------
package com.rbs.bdd.application.exception;

public class SecretsNotFoundException extends RuntimeException{
    public SecretsNotFoundException(String message){
        super(message);
    }

}



--------------
package com.rbs.bdd.application.exception;



/**
 * Exception thrown when schema Loading fails during SOAP request processing.
 */
public class XsdSchemaLoadingException extends RuntimeException{

    /**
     * Constructs a new XsdSchemaLoadingException with a specific message.
     *
     * @param message the detail message
     */
    public XsdSchemaLoadingException(String message) {
        super(message);
    }

    /**
     * Constructs a new XsdSchemaLoadingException with a message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public XsdSchemaLoadingException(String message,Throwable cause) {
        super(message, cause);
    }
}



--------------------
package com.rbs.bdd.common;

/**
 *
 * Error Codes definitions used accross validation logic.
 */
public class ErrorCodeConstants {

    /*Added a private constructor to hide the implicit public one.*/
    private ErrorCodeConstants(){};
    /*
   Generic error code used for business validations failures.
    */
    public static final String ERR_006="ERR006";
    public static final String ERR_10="0010";
    public static final String UNABLE_TO_COMPLETE_REQUEST="Unable to Complete Request";
}



--------------------
package com.rbs.bdd.domain.enums;


/**
 * Enum representing the status of the accounting unit.
 */
public enum AccountStatus {
    DOMESTIC_RESTRICTED("Domestic - Restricted"),
    DOMESTIC_UNRESTRICTED("Domestic - Unrestricted");

    private final String value;

    AccountStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}



-----------------
package com.rbs.bdd.domain.enums;


/**
 * Enum representing the Customer Name.
 */
public enum CustomerName {

    FIRST_NAME("ModifiedFirst"),
    LAST_NAME("ModifiedLast");

    private final String value;

    CustomerName(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

}



-----------------
package com.rbs.bdd.domain.enums;

/**
 * Enum to map known IBANs to first and last customer names.
 */
public enum CustomerNameMapping {

    IBAN_1("GB29NWBK60161331926801", "Alice", "Johnson","MR"),
    IBAN_2("GB82WEST12345698765437", "Bob", "Williams","MR"),
    IBAN_3("GB94BARC10201530093422", "Jenifer", "Brown","MRS"),
    IBAN_4("GB33BUKB20201555555567", "Jenny", "Smith","MRS");

    private final String iban;
    private final String firstName;
    private final String lastName;

    private final String prefixType;

    CustomerNameMapping(String iban, String firstName, String lastName,String prefixType) {
        this.iban = iban;
        this.firstName = firstName;
        this.lastName = lastName;
        this.prefixType=prefixType;
    }

    public String getIban() {
        return iban;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }
    public String getPrefixType() {
        return prefixType;
    }

    public static CustomerNameMapping fromIdentifier(String identifier) {
        for (CustomerNameMapping mapping : values()) {
            if (mapping.iban.equals(identifier) ||
                    mapping.iban.endsWith(identifier)) {
                return mapping;
            }
        }
        return null;
    }
}

----------------
package com.rbs.bdd.domain.enums;
import com.rbs.bdd.domain.model.ErrorDetail;
import com.rbs.bdd.domain.model.ErrorDetail;

import static com.rbs.bdd.common.ErrorCodeConstants.*;

/**
 * Enum representing predefined error types for validation responses.
 * Each constant wraps an {@link ErrorDetail} object with metadata used for SOAP fault construction.
 */
public enum ErrorConstants {


    ERR_INVALID_IBAN_LENGTH(new ErrorDetail("ERR006", UNABLE_TO_COMPLETE_REQUEST, "0013", "Length of IBAN is Invalid")),


    ERR_DB2_SQL(new ErrorDetail(ERR_006, "Service operation validateArrangementForPayment failed due to an error in the ESP. Contact systems management to resolve the problem.", null, null)),
    ERR_UBAN_GB(new ErrorDetail(ERR_006, "Service operation retrievePrimaryCustomerForArr failed due to an error in the ESP. Contact systems management to resolve the problem.", null, null)),

    ERR_WRONG_COUNTRY_CODE(new ErrorDetail(ERR_006, UNABLE_TO_COMPLETE_REQUEST, "0050", "SYSTEM_ERROR,incidentID=1f2ff299-9d93-41a5-9119-b4a552f0191e")),

    ERR_MOD97_IBAN(new ErrorDetail(ERR_006, UNABLE_TO_COMPLETE_REQUEST, "0020", "MOD97 failure for the IBAN")),

    ERR_INVALID_UBAN_LENGTH(new ErrorDetail(ERR_006, UNABLE_TO_COMPLETE_REQUEST, "0013", "100||INVALID SORT CODE OR ISSUING AUTH ID PASSED||Execution Successful")),

    ERR_CUSTOMER_NOT_FOUND(new ErrorDetail(ERR_006, UNABLE_TO_COMPLETE_REQUEST, "4", "Customer Not Found")),

    ERR_MOD97_UBAN(new ErrorDetail(ERR_006, "MOD97 failure for the UBAN", "0020", "MOD97 failure for the UBAN"));

    private final ErrorDetail detail;

    ErrorConstants(ErrorDetail detail) {
        this.detail = detail;
    }

    /**
     * Returns the {@link ErrorDetail} wrapped in this constant.
     */
    public ErrorDetail detail() {
        return detail;
    }

}

----------------
package com.rbs.bdd.domain.enums;

/**
 * Enum representing the result of modulus check validation.
 */
public enum ModulusCheckStatus {
    PASSED("Passed"),
    FAILED("Failed");

    private final String value;

    ModulusCheckStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}



---------------------

package com.rbs.bdd.domain.enums;

import java.util.List;

/**
 * Enum container for grouping constants related to service configuration, IBAN validation, file paths, and XPath expressions.
 * Constants are organized as nested interfaces for better readability and modular access.
 */
public enum ServiceConstants {
    // Empty enum just to hold grouped constants via nested interfaces
    ;

    /**
     * File paths for static response and error XMLs.
     */
    public final class  Paths {
        private Paths() {}
       public static final  String  ACCOUNT_VALIDATION_REQUEST="src/test/resources/static-request/account-validation-request.xml";
        public static final String  CUSTOMER_RETRIEVAL_REQUEST="src/test/resources/static-request/customer-retrieval-request.xml";

        public static final String ERROR_XML_PATH_FOR_CUSTOMER_RETRIEVAL= "error-response/error-response-customer-retrieval.xml";
        public static final String ACCOUNT_VALIDATION_SCHEMA_VALIDATION_ERROR_XML = "error-response/account-validation-schema-error.xml";
        public static final String CUSTOMER_SCHEMA_VALIDATION_ERROR_XML = "error-response/customer-retrieval-schema-error.xml";
        public static final String RESPONSE_XML_PATH = "static-response/account-validation/success-response.xml";
        public static final String ACCOUNT_VALIDATION_ERROR_XML = "error-response/account-validation-error.xml";

    }

    /**
     * Namespace URIs used in Spring WS handler for request mapping.
     */
    public final class  Namespaces {
        private Namespaces() {}
        public static final String NAMESPACE_URI_FOR_ACCOUNT_VALIDATION = "http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/";
        public static final String NAMESPACE_URI_FOR_CUSTOMER_RETRIEVAL = "http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/";
    }

    /**
     * Static IBANs used for known test scenarios.
     */
    public final class IBANs {
        private IBANs(){}
        public static final  String IBAN_1 = "GB29NWBK60161331926801";
        public static final String IBAN_2 = "GB82RBST12345698765437";
        public static final String IBAN_3 = "GB94UBNC10201530093422";
        public static final String IBAN_4 = "GB33RBSB20201555555567";



        public static final  List<String> ALL_IBANS = List.of(
                IBAN_1, IBAN_2, IBAN_3, IBAN_4
        );
    }

    /**
     * Code values used to distinguish between IBAN and UBAN.
     */
    public final class  AccountTypes {
        private AccountTypes(){}
        public static final String INTL_BANK_ACCOUNT = "InternationalBankAccountNumber";
        public static final String UK_BASIC_BANK_ACCOUNT = "UKBasicBankAccountNumber";
    }

    /**
     * XPath expressions for extracting and updating SOAP request/response values.
     */
    public final class  XPath {
        private XPath(){}
        public static final String XPATH_TRANSACTION_ID = "//*[local-name()='transactionId']";
        public static final String XPATH_HAS_PARTY_ASSOC="//*[local-name()='hasInvolvedPartyAssociation']";
        public static final  String XPATH_ASSOCIATED_PARTY=XPATH_HAS_PARTY_ASSOC+ "/*[local-name()='associatedInvolvedParty']";
        public static final String XPATH_FIRST_NAME =XPATH_ASSOCIATED_PARTY +
                "/*[local-name()='hasForName']/*[local-name()='firstName']";
        public static final String XPATH_PREFIX_TYPE = XPATH_ASSOCIATED_PARTY +
                "/*[local-name()='hasForName']/*[local-name()='prefixTitle']/*[local-name()='codeValue']";
        public static final  String XPATH_LAST_NAME = XPATH_ASSOCIATED_PARTY +
                "/*[local-name()='hasForName']/*[local-name()='lastName']";
        public static final String XPATH_ACCOUNT_STATUS = "//*[local-name()='accountingUnits']/*[local-name()='status']/*[local-name()='codeValue']";
        public static final String XPATH_SWITCHING_STATUS = "//*[local-name()='switchingStatus']/*[local-name()='codeValue']";
        public static final String XPATH_MODULUS_STATUS = "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']";

        // Fault-specific
        public static final String XPATH_FAULT_TRANSACTION_ID = "//*[local-name()='refRequestIds']/*[local-name()='transactionId']";
        public static final String XPATH_FAULT_RESPONSE_ID = "//*[local-name()='responseId']";
        public static final String XPATH_FAULT_TIMESTAMP = "//*[local-name()='timestamp']";

        /**
         * XPath to locate transactionId under responseId node.
         */
        public static final String XPATH_RESPONSE_ID_TXN_ID = "//*[local-name()='responseId']/*[local-name()='transactionId']";

        /**
         * XPath to locate transactionId under refRequestIds node.
         */
        public static final String XPATH_REF_REQUEST_TXN_ID = "//*[local-name()='refRequestIds']/*[local-name()='transactionId']";

        /**
         * XPath to locate cmdStatus node for command result status.
         */
        public static final String XPATH_CMD_STATUS = "//*[local-name()='cmdStatus']";

        /**
         * XPath to locate description node inside cmdNotifications block.
         */
        public static final String XPATH_CMD_DESCRIPTION = "//*[local-name()='cmdNotifications']/*[local-name()='description']";

        /**
         * XPath to locate timestamp node inside cmdNotifications block.
         */
        public static final String XPATH_TIMESTAMP = "//*[local-name()='cmdNotifications']/*[local-name()='timestamp']";

        /**
         * XPath to locate returnCode node inside cmdNotifications block.
         */
        public static final String XPATH_RETURN_CODE = "//*[local-name()='cmdNotifications']/*[local-name()='returnCode']";

        /**
         * XPath to locate description inside systemNotifications block.
         */
        public static final  String XPATH_SYS_NOTIFICATION_DESC = "//*[local-name()='systemNotifications']/*[local-name()='description']";

        /**
         * XPath to locate returnCode inside systemNotifications block.
         */
        public static final String XPATH_SYS_NOTIFICATION_CODE = "//*[local-name()='systemNotifications']/*[local-name()='returnCode']";

        /**
         * XPath to locate the entire systemNotifications block node.
         */
        public static final String XPATH_SYS_NOTIFICATION_BLOCK = "//*[local-name()='systemNotifications']";

    }

    /**
     * Common tag names.
     */
    public final class  Tags {
        private Tags(){}
        public static final String TAG_TRANSACTION_ID = "transactionId";
        public static final String SYSTEM_ID="systemId";
    }
}



---------------------------
package com.rbs.bdd.domain.enums;


/**
 * Enum representing switching status of the arrangement.
 */
public enum SwitchingStatus {
    SWITCHED("Switched"),
    NOT_SWITCHING("Not Switching");

    private final String value;

    SwitchingStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}




--------------------------------------
package com.rbs.bdd.domain.enums;

public enum ValidationErrorType {
    INVALID_PREFIX,

    INVALID_IBAN_LENGTH, INVALID_UBAN_LENGTH, INVALID_COUNTRY_CODE, INVALID_LENGTH, INVALID_MODULUS
}



------------------
package com.rbs.bdd.domain.model;



/**
 * Represents a structured error detail used for SOAP fault responses.
 * This record encapsulates:
 * <ul>
 *     <li>Error return code</li>
 *     <li>Human-readable description</li>
 *     <li>System notification code</li>
 *     <li>System notification description</li>
 * </ul>
 *
 * @param returnCode Unique identifier for the error
 * @param description User-friendly description of the error
 * @param systemNotificationCode Optional system-level notification code
 * @param systemNotificationDesc Optional system-level notification description
 */
public record ErrorDetail(
        String returnCode,
        String description,
        String systemNotificationCode,
        String systemNotificationDesc
) {}


--------------------
package com.rbs.bdd.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.EndpointInterceptor;

import java.io.ByteArrayOutputStream;
/**
 * Interceptor to log incoming and outgoing SOAP messages for debugging and monitoring.
 * This class logs the full request, response, and fault messages.
 */
@Slf4j
public class SoapLoggingInterceptor implements EndpointInterceptor {


    /**
     * Logs the incoming SOAP request before it reaches the endpoint.
     *
     * @param messageContext the message context containing the request
     * @param endpoint        the targeted endpoint
     * @return true to continue processing the request
     */
    @Override
    public boolean handleRequest(MessageContext messageContext, Object endpoint) {
        logMessage("SOAP Request", messageContext.getRequest());
        return true;
    }

    /**
     * Logs the outgoing SOAP response after the endpoint returns a result.
     *
     * @param messageContext the message context containing the response
     * @param endpoint        the targeted endpoint
     * @return true to continue processing the response
     */
    @Override
    public boolean handleResponse(MessageContext messageContext, Object endpoint) {
        logMessage("SOAP Response", messageContext.getResponse());
        return true;
    }

    /**
     * Logs the SOAP fault message if an exception occurs during processing.
     *
     * @param messageContext the message context containing the fault
     * @param endpoint        the targeted endpoint
     * @return true to continue processing the fault
     */
    @Override
    public boolean handleFault(MessageContext messageContext, Object endpoint) {
        logMessage("SOAP Fault", messageContext.getResponse());
        return true;
    }

    /**
     * Called after the completion of the message exchange.
     * No action is needed here, but method must be implemented.
     */
    @Override
    public void afterCompletion(MessageContext messageContext, Object endpoint, Exception ex) {
        // No action needed after completion
    }

    /**
     * Helper method to log the SOAP message by writing it to a byte array output stream.
     *
     * @param type    the type of SOAP message (Request, Response, Fault)
     * @param message the WebServiceMessage to be logged
     */
    private void logMessage(String type, org.springframework.ws.WebServiceMessage message) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            message.writeTo(out);  // Serialize the message to an output stream
            log.info("{}:\n{}", type, out.toString());  // Log the message content
        } catch (Exception e) {
            log.error("Error logging {} message: {}", type, e.getMessage());
        }
    }
}


-------------------
package com.rbs.bdd.infrastructure.config;

import com.rbs.bdd.application.exception.SchemaValidationException;
import com.rbs.bdd.application.exception.XsdSchemaLoadingException;
import com.rbs.bdd.infrastructure.soap.interceptor.AccountSchemaValidationInterceptor;
import com.rbs.bdd.infrastructure.soap.interceptor.CustomerSchemaValidationInterceptor;
import com.rbs.bdd.util.SoapInterceptorUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.XsdSchemaCollection;
import org.springframework.xml.xsd.commons.CommonsXsdSchemaCollection;
import java.util.List;

/**
 * Configures Spring Web Services (Spring WS) for the application.
 * <p>
 * This configuration includes:
 * <ul>
 *     <li>Publishing WSDL endpoints for SOAP web services</li>
 *     <li>Enabling automatic XML Schema (XSD) validation of incoming SOAP requests</li>
 *     <li>Registering interceptors for request validation</li>
 * </ul>
 */
@Configuration
@EnableWs
@Slf4j
public class SoapWebServiceConfig extends WsConfigurerAdapter {

    /**
     * Registers the {@link MessageDispatcherServlet} which is the main dispatcher for Spring WS.
     * It handles SOAP messages and dispatches them to appropriate endpoints.
     *
     * @param context the Spring application context
     * @return servlet registration bean mapped to the /ws/* URI
     */
    @Bean
    public ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(ApplicationContext context) {
        MessageDispatcherServlet servlet = new MessageDispatcherServlet();
        servlet.setApplicationContext(context);
        servlet.setTransformWsdlLocations(true);
        return new ServletRegistrationBean<>(servlet, "/ws/*");
    }

    /**
     * Adds a custom interceptor for schema validation. This interceptor validates incoming SOAP
     * messages against the configured XSD schema.
     *
     * @param interceptors list of interceptors to which this validation interceptor is added
     */
    @Override
    public void addInterceptors(List<EndpointInterceptor> interceptors) {

        log.debug(" Adding Interceptors");

        CustomerSchemaValidationInterceptor customerRetrievalInterceptor = new CustomerSchemaValidationInterceptor();
        customerRetrievalInterceptor.setValidateRequest(true);   // Validate incoming SOAP requests
        customerRetrievalInterceptor.setValidateResponse(false); // Do not validate outgoing responses
        try {
            customerRetrievalInterceptor.setXsdSchemaCollection(updateCustomerRetrievalXsd());
        } catch (Exception e) {
            throw new XsdSchemaLoadingException("Request XML Schema Validation failed", e);
        }
        interceptors.add(customerRetrievalInterceptor);

        AccountSchemaValidationInterceptor validatingInterceptor = new AccountSchemaValidationInterceptor();
        validatingInterceptor.setValidateRequest(true);   // Validate incoming SOAP requests
        validatingInterceptor.setValidateResponse(false); // Do not validate outgoing responses
        try {
            validatingInterceptor.setXsdSchemaCollection(updateContactXsd());
        } catch (Exception e) {
            throw new XsdSchemaLoadingException("Request XML Schema Validation failed", e);
        }
        interceptors.add(validatingInterceptor);


    }

    /**
     * Publishes a WSDL endpoint based on the `ArrValidationForPaymentParameters.xsd` file.
     * This exposes the WSDL dynamically under /ws/ArrValidationForPaymentParameters.wsdl
     *
     * @return a configured WSDL definition bean
     * @throws SchemaValidationException if XSD loading fails
     */
    @Bean(name = "ArrValidationForPaymentParameters")
    public DefaultWsdl11Definition accountValidationWSDL() throws SchemaValidationException {
        log.info("Account Validation Endpoint is invoked");
         return  SoapInterceptorUtils.buildWsdlDefinition(
                "IArrValidationForPayment",
                "http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/",
                updateContactXsd()
        );
    }

    /**
     * Loads the primary XSD schema (`ArrValidationForPaymentParameters.xsd`) from the classpath
     * and enables inlining for WSDL generation and schema validation.
     *
     * @return an XsdSchemaCollection used for both WSDL publishing and request validation
     * @throws XsdSchemaLoadingException if schema loading fails due to I/O or classpath errors
     */
    @Bean
    public XsdSchemaCollection updateContactXsd() {
        return SoapInterceptorUtils.loadSchema("xsd/account-validation/ArrValidationForPaymentParameters.xsd");

    }


    /**
     * Publishes a WSDL endpoint based on the `CustomerRetrievalForPaymentParameters.xsd` file.
     * This exposes the WSDL dynamically under /ws/CustomerRetrievalForPaymentParameters.wsdl
     *
     * @return a configured WSDL definition bean
     * @throws SchemaValidationException if XSD loading fails
     */
    @Bean(name = "CustomerRetrievalForPayment")
    public DefaultWsdl11Definition customerRetrievalWSDL() throws SchemaValidationException {
        log.info("Customer Retrieval Endpoint is invoked");
        return  SoapInterceptorUtils.buildWsdlDefinition(
                "ICustomerRetrievalForPayment",
                "http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/",
                updateCustomerRetrievalXsd()
        );
    }


    /**
     * Loads the primary XSD schema (`CustomerRetrievalForPaymentParameters.xsd`) from the classpath
     * and enables inlining for WSDL generation and schema validation.
     *
     * @return an XsdSchemaCollection used for both WSDL publishing and request validation
     * @throws XsdSchemaLoadingException if schema loading fails due to I/O or classpath errors
     */
    @Bean
    public XsdSchemaCollection updateCustomerRetrievalXsd() {
        return SoapInterceptorUtils.loadSchema("xsd/customer-retrieval/CustomerRetrievalForPaymentParameters.xsd");
    }


}

-------------------
package com.rbs.bdd.infrastructure.entity;
import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "customer_record")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustomerData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private UUID id;

    @Column(name = "account_no", nullable = false, unique = true)
    private String accountNo;

    @Column(name = "customer_prefix")
    private String prefixType;

    @Column(name = "customer_first_name")
    private String firstName;

    @Column(name = "customer_last_name")
    private String lastName;

    @Column(name = "account_type")
    private String accountType;


}

----------------
package com.rbs.bdd.infrastructure.repository;

import com.rbs.bdd.infrastructure.entity.CustomerData;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository public interface CustomerRepository extends JpaRepository<CustomerData, Long> {

    Optional<CustomerData> findByAccountNo(String accountNo);
}

--------------------
package com.rbs.bdd.infrastructure.soap.api;

import com.rbs.bdd.application.port.in.CustomerRetrievalPort;
import com.rbs.bdd.application.port.in.PaymentValidationPort;

import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

import static com.rbs.bdd.domain.enums.ServiceConstants.Namespaces.NAMESPACE_URI_FOR_ACCOUNT_VALIDATION;
import static com.rbs.bdd.domain.enums.ServiceConstants.Namespaces.NAMESPACE_URI_FOR_CUSTOMER_RETRIEVAL;


/**
 * SOAP endpoint adapter class for handling the `validateArrangementForPayment` operation.
 * It uses Spring WS annotations to route incoming SOAP requests to the appropriate service layer.
 */
@Slf4j
@Endpoint
public class PaymentValidationSoapAdapter {

    /**Changes for the request*/


    private final PaymentValidationPort paymentValidationPort;
    private final CustomerRetrievalPort customerRetrievalPort;

    /**
     * Constructor-based injection of the orchestrator that handles business logic.
     *
     * @param paymentValidationPort the orchestrator service
     */
    public PaymentValidationSoapAdapter(PaymentValidationPort paymentValidationPort,CustomerRetrievalPort customerRetrievalPort) {
        this.paymentValidationPort = paymentValidationPort;
        this.customerRetrievalPort = customerRetrievalPort;
    }



    /**
     * Handles the `validateArrangementForPayment` SOAP request.
     * Delegates request processing to the orchestrator which modifies the response message directly.
     *
     * @param request the SOAP request payload
     * @param context the Spring WS message context
     */
    @PayloadRoot(namespace = NAMESPACE_URI_FOR_ACCOUNT_VALIDATION, localPart = "validateArrangementForPayment")
    @ResponsePayload
    public void validateArrangementForPayment(@RequestPayload ValidateArrangementForPaymentRequest request,
                                                MessageContext context) {
        log.info("validateArrangementForPayment is called");
        WebServiceMessage response = context.getResponse();
        paymentValidationPort.validateArrangementForPayment(request, response);
         }

    /**
     * Handles the `RetrieveCustomerRequest` SOAP request.
     * Delegates request processing to the orchestrator which modifies the response message directly.
     *
     * @param request the SOAP request payload
     * @param context the Spring WS message context
     */
    @PayloadRoot(namespace = NAMESPACE_URI_FOR_CUSTOMER_RETRIEVAL, localPart = "retrievePrimaryCustomerForArr")
    @ResponsePayload
    public void validateCustomerRetrieval(@RequestPayload RetrievePrimaryCustomerForArrRequest request,
                                              MessageContext context) {
        log.info("validateCustomerRetrieval is called");
        WebServiceMessage response = context.getResponse();

        customerRetrievalPort.validateCustomerRetrieval(request, response);
    }

}



---------------
package com.rbs.bdd.infrastructure.soap.interceptor;


import com.rbs.bdd.application.exception.SchemaValidationException;
import com.rbs.bdd.util.SoapInterceptorUtils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.server.endpoint.interceptor.PayloadValidatingInterceptor;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.InputStream;
import static com.rbs.bdd.domain.enums.ServiceConstants.Namespaces.NAMESPACE_URI_FOR_ACCOUNT_VALIDATION;
import static com.rbs.bdd.domain.enums.ServiceConstants.Paths.ACCOUNT_VALIDATION_SCHEMA_VALIDATION_ERROR_XML;


/**
 * Intercepts schema validation errors in SOAP requests and returns a custom SOAP fault response.
 * The response is based on a static XML file, with dynamic fields replaced using request data.
 */
@Slf4j
public class AccountSchemaValidationInterceptor extends PayloadValidatingInterceptor {




    @Override
    public boolean handleRequest(MessageContext messageContext, Object endpoint) throws IOException, TransformerException, SAXException {
        if (SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(messageContext, NAMESPACE_URI_FOR_ACCOUNT_VALIDATION)) {
            return true;
        }
        return super.handleRequest(messageContext, endpoint);
    }


    /**
     * Handles schema validation failures by generating a custom SOAP fault response.
     * Modifies a static error XML template based on the request content and sends it with HTTP 500.
     *
     * @param messageContext the message context
     * @param errors         the validation errors
     * @return false to prevent Spring WS from overriding with default fault
     */
    @Override
    public boolean handleRequestValidationErrors(MessageContext messageContext, SAXParseException[] errors) {
        log.warn("Schema validation failed. Returning custom schemaValidationError.xml");
        return SoapInterceptorUtils.handleSchemaValidationErrors(messageContext
                ,ACCOUNT_VALIDATION_SCHEMA_VALIDATION_ERROR_XML,"accountValidation");
    }



    /**
     * Retrieves static XML file from classpath. Can be overridden in tests.
     *
     * @param path the classpath location of the file
     * @return input stream for the XML file
     */
    protected InputStream getClassLoaderResource(String path) {
        return getClass().getClassLoader().getResourceAsStream(path);
    }

}


----------
package com.rbs.bdd.infrastructure.soap.interceptor;



import com.rbs.bdd.util.SoapInterceptorUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.server.endpoint.interceptor.PayloadValidatingInterceptor;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.InputStream;
import static com.rbs.bdd.domain.enums.ServiceConstants.Namespaces.NAMESPACE_URI_FOR_CUSTOMER_RETRIEVAL;
import static com.rbs.bdd.domain.enums.ServiceConstants.Paths.CUSTOMER_SCHEMA_VALIDATION_ERROR_XML;


/**
 * Intercepts schema validation errors in SOAP requests and returns a custom SOAP fault response.
 * The response is based on a static XML file, with dynamic fields replaced using request data.
 */
@Slf4j
public class CustomerSchemaValidationInterceptor extends PayloadValidatingInterceptor {




    @Override
    public boolean handleRequest(MessageContext messageContext, Object endpoint) throws IOException, TransformerException, SAXException {
        if (SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(messageContext, NAMESPACE_URI_FOR_CUSTOMER_RETRIEVAL)) {
            return true;
        }
        return super.handleRequest(messageContext, endpoint);
    }


    /**
     * Handles schema validation failures by generating a custom SOAP fault response.
     * Modifies a static error XML template based on the request content and sends it with HTTP 500.
     *
     * @param messageContext the message context
     * @param errors         the validation errors
     * @return false to prevent Spring WS from overriding with default fault
     */
    @Override
    public boolean handleRequestValidationErrors(MessageContext messageContext, SAXParseException[] errors) {
        log.error("Schema validation failed. Returning custom schemaValidationError.xml");
        return SoapInterceptorUtils.handleSchemaValidationErrors(messageContext,
                CUSTOMER_SCHEMA_VALIDATION_ERROR_XML,"customerRetrieval");
    }


    /**
     * Retrieves static XML file from classpath. Can be overridden in tests.
     *
     * @param path the classpath location of the file
     * @return input stream for the XML file
     */
    protected InputStream getClassLoaderResource(String path) {
        return getClass().getClassLoader().getResourceAsStream(path);
    }

}

------------------
package com.rbs.bdd.util;

import com.rbs.bdd.application.exception.SchemaValidationException;
import com.rbs.bdd.application.exception.XsdSchemaLoadingException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.XsdSchemaCollection;
import org.springframework.xml.xsd.commons.CommonsXsdSchemaCollection;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import static com.rbs.bdd.domain.enums.ServiceConstants.Tags.SYSTEM_ID;
import static com.rbs.bdd.domain.enums.ServiceConstants.Tags.TAG_TRANSACTION_ID;
import static com.rbs.bdd.util.ValidationUtils.*;

@Slf4j
public class SoapInterceptorUtils {
    private SoapInterceptorUtils(){}
    private static final String PLACEHOLDER_TXN = "TXN_ID_PLACEHOLDER";
    private static final String PLACEHOLDER_RESPONSE = "RESPONSE_ID_PLACEHOLDER";

    /**
     * Retrieves the text content of a given tag from the request document.
     */
    public static String getValueFromRequest(Document doc, String tag) {
        NodeList list = doc.getElementsByTagNameNS("*", tag);
        return list.getLength() > 0 ? list.item(0).getTextContent() : null;
    }


    /**
     * Replaces a text node matching a placeholder with a new value.
     */
    public static void replaceTextNode(Document doc, String placeholder, String newValue) {
        NodeList nodes = doc.getElementsByTagNameNS("*", TAG_TRANSACTION_ID);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node txn = nodes.item(i);
            if (placeholder.equals(txn.getTextContent())) {
                txn.setTextContent(newValue);
            }
        }
    }

    /**
     * Sends the final SOAP error response with HTTP 500.
     */
    public static void sendCustomSoapFault(Document errorDoc) throws TransformerException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new DOMSource(errorDoc), new StreamResult(out));
        HttpServletResponse servletResponse =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
        if (servletResponse != null && !servletResponse.isCommitted()) {
            servletResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            servletResponse.setContentType("text/xml;charset=UTF-8");
            servletResponse.getOutputStream().write(out.toByteArray());
            servletResponse.flushBuffer();}
    }

    /**
     * Creates a secure, namespace-aware {@link DocumentBuilderFactory}.
     * <p>
     * This method disables external entity processing to prevent XML External Entity (XXE)
     * attacks and other injection vulnerabilities.
     * @return configured {@link DocumentBuilderFactory} instance
     * @throws ParserConfigurationException if security features cannot be set
     */
    public static DocumentBuilder getSecureDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder();
    }
    public static boolean skipInterceptorIfNamespaceNotMatched(MessageContext messageContext, String expectedNamespace) {
        try {
            WebServiceMessage request = messageContext.getRequest();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            request.writeTo(out);
            String xml =out.toString();
            if (!xml.contains(expectedNamespace)) {
                return true;
            }
        } catch (Exception e) {
            log.error("Error in namespace filtering", e);
        }
        return false;
    }

    public static XsdSchemaCollection loadSchema(String path)
    {
        try {
            CommonsXsdSchemaCollection xsd = new CommonsXsdSchemaCollection(
                    new ClassPathResource(path));
            xsd.setInline(true);
            return xsd;
        } catch (Exception e) {
            throw new XsdSchemaLoadingException("Failed to load XSD schema for SOAP validation", e);
        }
    }

    public static DefaultWsdl11Definition buildWsdlDefinition( String portType, String namespace, XsdSchemaCollection schemaCollection)
    {
        DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
        wsdl11Definition.setPortTypeName(portType);
        wsdl11Definition.setLocationUri("/ws");
        wsdl11Definition.setTargetNamespace(namespace);
        wsdl11Definition.setSchemaCollection(schemaCollection);
        return wsdl11Definition;
    }

    /**
     * Parses the incoming request message into a Document.
     */
    public static Document extractRequestDocument(MessageContext messageContext, DocumentBuilder builder) throws IOException, SAXException {
        WebServiceMessage request = messageContext.getRequest();
        ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
        request.writeTo(requestBytes);
        return builder.parse(new ByteArrayInputStream(requestBytes.toByteArray()));
    }


    /**
     * Handles schema validation failures by generating a custom SOAP fault response.
     * Modifies a static error XML template based on the request content and sends it with HTTP 500.
     *
     * @param messageContext the message context
     * @return false to prevent Spring WS from overriding with default fault
     */

    public static boolean handleSchemaValidationErrors(MessageContext messageContext, String errorPath, String filter) {
        log.warn("Schema validation failed. Returning custom schemaValidationError.xml");
        try (InputStream staticXml = SoapInterceptorUtils.class.getClassLoader().getResourceAsStream(errorPath)) {
            if (staticXml == null) {
                log.error("schemaValidationError.xml not found");
                return true;
            }
            DocumentBuilder builder = SoapInterceptorUtils.getSecureDocumentBuilder();
            Document errorDoc = builder.parse(staticXml);
            Document requestDoc = SoapInterceptorUtils.extractRequestDocument(messageContext, builder);
            if(filter.equals("accountValidation")){
                updateDynamicFields(errorDoc, requestDoc);}
            else{
                updateFields(errorDoc, requestDoc);
            }
            SoapInterceptorUtils.sendCustomSoapFault(errorDoc);
            return false;
        } catch (Exception e) {
            log.error("Error during schema validation interception", e);
            throw new SchemaValidationException("Schema validation failure", e);
        }
    }

    /**
     * Updates transaction ID, timestamp, and cleans up the response XML dynamically.
     */
    private static void updateDynamicFields(Document errorDoc, Document requestDoc) throws XPathExpressionException {
        String txnId = SoapInterceptorUtils.getValueFromRequest(requestDoc, TAG_TRANSACTION_ID);
        String systemId = SoapInterceptorUtils.getValueFromRequest(requestDoc, SYSTEM_ID);

        SoapInterceptorUtils.replaceTextNode(errorDoc, PLACEHOLDER_RESPONSE, generateTxnId());
        SoapInterceptorUtils.replaceTextNode(errorDoc, PLACEHOLDER_TXN, txnId != null ? txnId : PLACEHOLDER_TXN);
        setXPathValue(errorDoc, "//*[local-name()='timestamp']",
                OffsetDateTime.now(ZoneId.of("Europe/London")).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        handleRefRequestIds(errorDoc, requestDoc, txnId, systemId);
    }
    /**
     * Handles removal of <refRequestIds> node if <requestIds> is missing or empty.
     */
    private static void handleRefRequestIds(Document errorDoc, Document requestDoc, String txnId, String systemId) {
        Node requestIds = getNode(requestDoc, "requestIds");
        Node refRequestIds = getNode(errorDoc, "refRequestIds");

        if (shouldRemoveEntireRefRequestIds(requestIds, refRequestIds)) return;

        if (refRequestIds != null) {
            removeMissingChildNodes(refRequestIds, txnId, systemId);
            removeIfEmpty(refRequestIds);
        }
    }

    private static boolean shouldRemoveEntireRefRequestIds(Node requestIds, Node refRequestIds) {
        if (isNodeEmpty(requestIds) && refRequestIds != null) {
            refRequestIds.getParentNode().removeChild(refRequestIds);
            return true;
        }
        return false;
    }

    private static void removeMissingChildNodes(Node refRequestIds, String txnId, String systemId) {
        if (txnId == null) removeNodes(refRequestIds, TAG_TRANSACTION_ID);
        if (systemId == null) removeNodes(refRequestIds, SYSTEM_ID);
    }

    private static void removeIfEmpty(Node node) {
        if (!node.hasChildNodes()) {
            node.getParentNode().removeChild(node);
        }
    }

    /**
     * Updates transaction ID, timestamp, and cleans up the response XML dynamically.
     */
    private static void updateFields(Document errorDoc, Document requestDoc) throws XPathExpressionException {
        String txnId = SoapInterceptorUtils.getValueFromRequest(requestDoc, TAG_TRANSACTION_ID);
        SoapInterceptorUtils.replaceTextNode(errorDoc, PLACEHOLDER_RESPONSE, generateTxnId());
        SoapInterceptorUtils. replaceTextNode(errorDoc, PLACEHOLDER_TXN, txnId != null ? txnId : PLACEHOLDER_TXN);
        setXPathValue(errorDoc, "//*[local-name()='timestamp']",
                OffsetDateTime.now(ZoneId.of("Europe/London")).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        handleRequestIds(errorDoc, requestDoc);
    }

    /**
     * Handles removal of {@code <refRequestIds>} node in the error response
     * if {@code <requestIds>} is missing or missing specific fields (systemId, transactionId).
     * @param errorDoc   the static error XML document
     * @param requestDoc the SOAP request XML document
     */
    public static void handleRequestIds(Document errorDoc, Document requestDoc) {
        NodeList requestIdNodes = requestDoc.getElementsByTagNameNS("*", "requestIds");
        Node refRequestIds = getNode(errorDoc, "refRequestIds");
        ValidationFlags flags = extractValidationFlags(requestIdNodes);
        if (refRequestIds != null) {
            handleRefRequestIds(refRequestIds, flags);}
    }

    /**
     * Extracts flags from the request's {@code <requestIds>} elements.
     * Determines if a node with {@code systemId = "RequestID"} exists,
     * and whether it contains {@code <transactionId>} and {@code <systemId>} sub-elements.
     *
     * @param requestIdNodes list of {@code <requestIds>} elements in the request
     * @return a record with flags indicating presence of required fields
     */
    private static ValidationFlags extractValidationFlags(NodeList requestIdNodes) {
        for (int i = 0; i < requestIdNodes.getLength(); i++) {
            Node requestIdsNode = requestIdNodes.item(i);
            NodeList children = requestIdsNode.getChildNodes();
            ValidationFlags flags = analyzeRequestIdChildren(children);
            if (flags.foundRequestIDSystemId()) {
                return flags;
            }
        }
        return new ValidationFlags(false, false, false);
    }

    /**
     * Analyzes the children of a {@code <requestIds>} node to determine
     * whether it contains a valid "RequestID" systemId and presence of specific sub-elements.
     *
     * @param children NodeList of child elements inside a {@code <requestIds>} node
     * @return ValidationFlags record indicating which tags are present
     */
    private static ValidationFlags analyzeRequestIdChildren(NodeList children) {
        boolean txnIdPresent = false;
        boolean systemIdPresent = false;
        String systemId = null;

        for (int j = 0; j < children.getLength(); j++) {
            Node child = children.item(j);
            String tag = child.getLocalName();

            if (SYSTEM_ID.equals(tag)) {
                systemId = child.getTextContent();
                systemIdPresent = true;
            } else if (TAG_TRANSACTION_ID.equals(tag)) {
                txnIdPresent = true;
            }
        }

        boolean isRequestID = "RequestID".equals(systemId);
        return new ValidationFlags(isRequestID, txnIdPresent, systemIdPresent);
    }
    /**
     * Handles logic for modifying or removing {@code <refRequestIds>} in the error response
     * based on the extracted validation flags.
     *
     * @param refRequestIds the {@code <refRequestIds>} node in error XML
     * @param flags         extracted field presence indicators
     */
    private static void handleRefRequestIds(Node refRequestIds, ValidationFlags flags) {
        if (!flags.foundRequestIDSystemId()) {
            removeChildNode(refRequestIds,null);
            return;}
        if (!flags.hasTxnId()) {
            removeChildNode(refRequestIds, TAG_TRANSACTION_ID);}
        if (!flags.hasSystemId()) {
            removeChildNode(refRequestIds, SYSTEM_ID);}
        if (!refRequestIds.hasChildNodes()) {
            removeChildNode(refRequestIds,null);
        }
    }



    /**
     * A container for boolean flags used to control the logic for request ID validation.
     * @param foundRequestIDSystemId whether a {@code <requestIds>} block with systemId=RequestID exists
     * @param hasTxnId               whether the matching block has a {@code <transactionId>}
     * @param hasSystemId            whether the matching block has a {@code <systemId>}
     */
    @SuppressWarnings("unused")
    private record ValidationFlags(boolean foundRequestIDSystemId, boolean hasTxnId, boolean hasSystemId) {
        // This method has no methods or logic because it is purily a data carrier
    }


}

-----------------
package com.rbs.bdd.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;

import com.rbs.bdd.application.service.AccountValidationService;
import com.rbs.bdd.domain.enums.ServiceConstants;
import com.rbs.bdd.domain.enums.ValidationErrorType;
import com.rbs.bdd.domain.model.ErrorDetail;
import jakarta.xml.soap.SOAPException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

/**
 * Utility class for validating account identifiers like IBAN or UBAN
 * across different service contexts such as Account Validation or Customer Retrieval.
 * <p>
 * This class centralizes error evaluation logic based on account type, identifier format,
 * length, and modulus check results.
 */
@Slf4j
public class ValidationUtils {
    /**
     * Immutable container representing a valid request configuration.
     * this record is left without methods or additional logic,as it is only
     *  used to group and transport request fields such as
     *  <ul>
     *     <li>{@code identifier} - contains account number </li>
     *     <li>{@code codeValue} - used to identify
     * whether account is UKBasicBankAccountNumber or InternationalBankAccountNumber</li>
     *      <li>{@code originalTxnId} - return the transactionId of the request </li>
     *       <li>{@code systemId} - returns the systemId from the request </li>
     *       </ul>
     */
    @SuppressWarnings("unused")
    public record RequestParams(String identifier, String codeValue, String originalTxnId, String systemId) {
        // this record is left without methods or additional logic,as it is only used to group and transport request fields

    }


    /**
     * Checks if the given node is empty or only contains non-element children.
     */
    public static boolean isNodeEmpty(Node node) {
        if (node == null) return true;
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == Node.ELEMENT_NODE) return false;
        }
        return true;
    }

    /**
     * Removes a specific child element from the parent node.
     */
    public static void removeNodes(Node parent, String tagName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (tagName.equals(child.getLocalName())) {
                parent.removeChild(child);
                break;
            }
        }
    }

    /**
     * Validates the provided {@link RequestParams} based on predefined rules for
     * account type (UK Basic or International) and returns a mapped {@link ErrorDetail}
     * from the provided {@code errorMap} based on failure conditions.
     * <p>
     * This method is reusable across multiple services and logs the validation
     * outcome per service context.
     * @param p              the request parameter object containing account details
     * @param errorMap       a mapping of {@link ValidationErrorType} to corresponding {@link ErrorDetail}
     * @param ibanValidator  a predicate used to validate IBAN or UBAN using modulus or custom rule
     * @param serviceContext a string to log the calling service (e.g., "AccountValidation", "CustomerRetrieval")
     * @return an {@code Optional<ErrorDetail>} containing the matched error if validation fails; empty otherwise
     */
    public static Optional<ErrorDetail> validateAccount(
            RequestParams p,
            Map<ValidationErrorType, ErrorDetail> errorMap,
            Predicate<String> ibanValidator,
            String serviceContext
    ) {
        if (ServiceConstants.AccountTypes.UK_BASIC_BANK_ACCOUNT.equals(p.codeValue())) {
            log.info("Account Type is :"+ ServiceConstants.AccountTypes.UK_BASIC_BANK_ACCOUNT);
            return validateUbanAccount(p, errorMap, ibanValidator, serviceContext);
        }

        if (ServiceConstants.AccountTypes.INTL_BANK_ACCOUNT.equals(p.codeValue())) {
            log.info("Account Type is :"+ServiceConstants.AccountTypes.INTL_BANK_ACCOUNT);
            return validateIbanAccount(p, errorMap, serviceContext);
        }

        return Optional.empty();
    }

    /**
     * Validates a UK Basic Bank Account (UBAN).
     */
    private static Optional<ErrorDetail> validateUbanAccount(
            RequestParams p,
            Map<ValidationErrorType, ErrorDetail> errorMap,
            Predicate<String> ibanValidator,
            String context
    ) {
        if (!p.identifier().matches("\\d+")) {
            log.error("UBAN account is starting with GB prefix");
            return Optional.of(errorMap.get(ValidationErrorType.INVALID_PREFIX));
        }

        if (p.identifier().length() != 14) {
            log.error("UBAN account is not equal to 14 characters");
            return Optional.of(context.equals("CustomerRetrieval")
                    ? errorMap.get(ValidationErrorType.INVALID_LENGTH)
                    : errorMap.get(ValidationErrorType.INVALID_UBAN_LENGTH));
        }

        if (!ibanValidator.test(p.identifier())) {
            log.error("UBAN account is not valid");
            return Optional.of(errorMap.get(ValidationErrorType.INVALID_MODULUS));
        }

        log.info("No error for UBAN [{}] in {} with identifier: {}", p.codeValue(), context, p.identifier());
        return Optional.empty();
    }

    /**
     * Validates an International Bank Account Number (IBAN).
     */
    private static Optional<ErrorDetail> validateIbanAccount(
            RequestParams p,
            Map<ValidationErrorType, ErrorDetail> errorMap,
            String context
    ) {

        if (!p.identifier().startsWith("GB")) {
            log.error("IBAN account is not starting with GB prefix");
            return Optional.of(context.equals("CustomerRetrieval")
                    ? errorMap.get(ValidationErrorType.INVALID_PREFIX)
                    : errorMap.get(ValidationErrorType.INVALID_COUNTRY_CODE));
        }

        if (p.identifier().length() != 22) {
            log.error("IBAN account is not equal to 22 characters");
            return Optional.of(context.equals("CustomerRetrieval")
                    ? errorMap.get(ValidationErrorType.INVALID_LENGTH)
                    : errorMap.get(ValidationErrorType.INVALID_IBAN_LENGTH));

        }

        log.info("No error for IBAN [{}] in {} with identifier: {}", p.codeValue(), context, p.identifier());
        return Optional.empty();
    }




    /**
     * Generates a unique transaction ID using UUID.
     */
    public static String generateTxnId() {
        return "1alN" + UUID.randomUUID().toString().replace("-", "") + "h";
    }
    /**
     * Removes a child node from the specified parent node.
     * <ul>
     *     <li>If {@code tagName} is {@code null}, it removes the node directly from its parent.</li>
     *     <li>If {@code tagName} is provided, it searches the children of the parent node and removes the first match based on local name.</li>
     * </ul>
     *
     * @param parentOrNode the node to be removed directly (if {@code tagName} is null), or parent node (if tagName is provided)
     * @param tagName       the local name of the child node to remove; {@code null} for direct removal
     */
    public static void removeChildNode(Node parentOrNode, String tagName) {
        if (tagName == null) {
            removeDirectNode(parentOrNode);
        } else {
            removeChildByTag(parentOrNode, tagName);
        }
    }

    /**
     * Sets a value for the node matching the given XPath expression.
     */
    public static void setXPathValue(Document doc, String path, String value) throws XPathExpressionException {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null) {
            node.setTextContent(value);
        }
    }

    /**
     * Removes the given node from its parent if both are non-null.
     */
    private static void removeDirectNode(Node node) {
        if (node != null && node.getParentNode() != null) {
            node.getParentNode().removeChild(node);
        }
    }

    /**
     * Removes the first child of the parent that matches the given local tag name.
     */
    private static void removeChildByTag(Node parent, String tagName) {
        if (parent == null || tagName == null) return;

        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (tagName.equals(child.getLocalName())) {
                parent.removeChild(child);
                break;
            }
        }
    }

    /**
     * Finds a node by its local name using wildcard namespace.
     */
    public static Node getNode(Document doc, String localName) {
        NodeList nodes = doc.getElementsByTagNameNS("*", localName);
        return nodes.getLength() > 0 ? nodes.item(0) : null;
    }

    public static  void writeResponseToSoapMessage(WebServiceMessage message, Document responseDoc) throws TransformerException, SOAPException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(new DOMSource(responseDoc), new StreamResult(out));
        ((SaajSoapMessage) message).getSaajMessage().getSOAPPart()
                .setContent(new StreamSource(new ByteArrayInputStream(out.toByteArray())));
    }



}


---------------
package com.rbs.bdd;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;


/**

 * Main Spring boot entry class for the Esp Simulator application.
 * This class bootstraps the spring context and launches the application.

 * Main Spring boot entry class for the Esp Simulator application.
 * This class bootstraps the spring context and launches the application.
 */
@ComponentScan("com.rbs.bdd")
@SpringBootApplication(scanBasePackages = "com.rbs.bdd" )
       // ,exclude = {org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration.class})
public class EspSimulatorEngine {

    public static void main(String[] args) {
        SpringApplication.run(EspSimulatorEngine.class, args);
    }
}



-------------------
Now in the resources foler :-
db.changelog->rbs->customer_retrieval_request


create-customer-info-tables.yaml file



databaseChangeLog:
  - changeSet:
      id: create-esp-simulation-record-table
      author: esp-simulation-service
      changes:
        - createTable:
            tableName: customer_record
            columns:
              - column:
                  name: id
                  type: UUID
                  constraints:
                    primaryKey: true
                    nullable: false
                  defaultValueComputed: gen_random_uuid()
              - column:
                  name: account_no
                  type: varchar(50)
                  constraints:
                    unique: true
                    nullable: false
              - column:
                  name: account_type
                  type: varchar(50)
                  constraints:
                    nullable: false
              - column:
                  name: customer_prefix
                  type: varchar(20)
                  constraints:
                    nullable: false
              - column:
                  name: customer_first_name
                  type: varchar(20)
                  constraints:
                    nullable: false
              - column:
                  name: customer_last_name
                  type: varchar(20)
                  constraints:
                    nullable: false

  - changeSet:
      id: insert-esp-simulation-record-1
      author: esp-simulation-service
      changes:
        - insert:
            tableName: customer_record
            columns:
              - column:
                  name: account_no
                  value: GB29NWBK60161331926201
              - column:
                  name: account_type
                  value: InternationalBankAccountNumber
              - column:
                  name: customer_prefix
                  value: MRS
              - column:
                  name: customer_first_name
                  value: Alisa
              - column:
                  name: customer_last_name
                  value: Johnson
        - insert:
            tableName: customer_record
            columns:
              - column:
                  name: account_no
                  value: GB29NWBK60161331926401
              - column:
                  name: account_type
                  value: InternationalBankAccountNumber
              - column:
                  name: customer_prefix
                  value: MR
              - column:
                  name: customer_first_name
                  value: Alexander
              - column:
                  name: customer_last_name
                  value: Gram
        - insert:
            tableName: customer_record
            columns:
              - column:
                  name: account_no
                  value: GB29NWBK60161331926501
              - column:
                  name: account_type
                  value: InternationalBankAccountNumber
              - column:
                  name: customer_prefix
                  value: MR
              - column:
                  name: customer_first_name
                  value: Antony
              - column:
                  name: customer_last_name
                  value: Nason
        - insert:
            tableName: customer_record
            columns:
              - column:
                  name: account_no
                  value: 60161331926501
              - column:
                  name: account_type
                  value: UKBasicBankAccountNumber
              - column:
                  name: customer_prefix
                  value: MRS
              - column:
                  name: customer_first_name
                  value: Simmi
              - column:
                  name: customer_last_name
                  value: Nason


------------------
db.changelog->db->db.changelog-master.yaml



databaseChangeLog:
  - changeSet:
      id: initial-commit
      author: esp-simulation-service

  - include:
      file: db/changelog/rbs/customer_retrieval_request/create-customer-info-tables.yaml





-----------------
resources->error_response


account-validation-error.xml


<soapenv:Envelope xmlns:nsVer="http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">

    <soapenv:Body>
        <nsVer:validateArrangementForPaymentResponse>

        <exception>
                <responseId>
                    <systemId>ESP</systemId>
                    <transactionId>RESPONSE_ID_PLACEHOLDER</transactionId>
                </responseId>
                <refRequestIds>
                    <systemId>RequestID</systemId>
                    <transactionId>TXN_ID_PLACEHOLDER</transactionId>
                </refRequestIds>
                <operatingBrand>ALL</operatingBrand>
                <serviceName>ArrValidationForPayment</serviceName>
                <operationName>validateArrangementForPayment</operationName>
                <cmdStatus>Failed</cmdStatus>
                <cmdNotifications>
                    <returnCode>ERR006</returnCode>
                    <category>Error</category>
                    <description>Unable to Complete Request</description>
                    <timestamp>2025-06-01T00:00:00.000+01:00</timestamp>
                    <systemNotifications>
                        <returnCode>0010</returnCode>
                        <category>Error</category>
                        <description>System notification placeholder</description>
                        <processingId>
                            <systemId>PMP</systemId>
                        </processingId>
                    </systemNotifications>
                </cmdNotifications>
            </exception>
        </nsVer:validateArrangementForPaymentResponse>
    </soapenv:Body>
</soapenv:Envelope>

---------------------

   resources->error_response


account-validation-schema-error.xml


<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header/>
    <soap:Body>
        <tns:validateArrangementForPaymentResponse xmlns:tns="http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/">
            <exception>
                <responseId>
                    <systemId>ESP</systemId>
                    <transactionId>RESPONSE_ID_PLACEHOLDER</transactionId>
                </responseId>
                <refRequestIds>
                    <systemId>RequestID</systemId>
                    <transactionId>TXN_ID_PLACEHOLDER</transactionId>
                </refRequestIds>
                <operatingBrand>ALL</operatingBrand>
                <serviceName>ArrValidationForPayment</serviceName>
                <operationName>validateArrangementForPayment</operationName>
                <cmdStatus>Failed</cmdStatus>
                <cmdNotifications>
                    <returnCode>ERR001</returnCode>
                    <category>Error</category>
                    <description>Message Not Formatted Correctly. Validation of the message failed in the request, response or exception e.g. XSD or WSDL validations. The input message has failed schema validation for service operation validateArrangementForPayment.</description>
                    <timestamp>TIMESTAMP_PLACEHOLDER</timestamp>
                </cmdNotifications>
            </exception>
        </tns:validateArrangementForPaymentResponse>
    </soap:Body>
</soap:Envelope>


-----------------------

   resources->error_response


customer-retrieval-schema-error.xml


<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header/>
    <soap:Body>
        <tns:retrievePrimaryCustomerForArrResponse xmlns:tns="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/">
            <exception>
                <responseId>
                    <systemId>ESP</systemId>
                    <transactionId>RESPONSE_ID_PLACEHOLDER</transactionId>
                </responseId>
                <refRequestIds>
                    <systemId>RequestID</systemId>
                    <transactionId>TXN_ID_PLACEHOLDER</transactionId>
                </refRequestIds>
                <refRequestIds>
                    <systemId>SourceID</systemId>
                    <transactionId>ISO</transactionId>
                </refRequestIds>
                <operatingBrand>ALL</operatingBrand>
                <serviceName>CustomerRetrievalForPayment</serviceName>
                <operationName>retrievePrimaryCustomerForArr</operationName>
                <cmdStatus>Failed</cmdStatus>
                <cmdNotifications>
                    <returnCode>ERR001</returnCode>
                    <category>Error</category>
                    <description>Message Not Formatted Correctly. Validation of the message failed in the request, response or exception e.g. XSD or WSDL validations. The input message has failed schema validation for service operation retrievePrimaryCustomerForArr.</description>
                    <timestamp>TIMESTAMP_PLACEHOLDER</timestamp>
                </cmdNotifications>
            </exception>
        </tns:retrievePrimaryCustomerForArrResponse>
    </soap:Body>
</soap:Envelope>


--------------------------

error-response-customer-retrieval.xml

<NS1:Envelope xmlns:NS1="http://schemas.xmlsoap.org/soap/envelope/">
    <NS1:Body>
        <NS2:retrievePrimaryCustomerForArrResponse xmlns:NS2="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/">
            <exception>
                <responseId>
                    <systemId>ESP</systemId>
                    <transactionId>5flS3ea4afb79684c151812aa79c320250613131000581h</transactionId>
                </responseId>
                <refRequestIds>
                    <systemId>RequestID</systemId>
                    <transactionId>NCO-E2EINTL-BTC8</transactionId>
                </refRequestIds>
                <refRequestIds>
                    <systemId>SourceID</systemId>
                    <transactionId>PIM</transactionId>
                </refRequestIds>
                <operatingBrand>NWB</operatingBrand>
                <serviceName>CustomerRetrievalForPayment</serviceName>
                <operationName>retrievePrimaryCustomerForArr</operationName>
                <cmdStatus>Failed</cmdStatus>
                <cmdNotifications>
                    <returnCode>ERR006</returnCode>
                    <category>Error</category>
                    <description>Service operation retrievePrimaryCustomerForArr failed due to an error in the ESP. Contact systems management to resolve the problem.</description>
                    <timestamp>2025-06-13T13:10:00.591413+01:00</timestamp>
                    <systemNotifications>
                        <returnCode>4</returnCode>
                        <category>Error</category>
                        <description>Customer Not Found</description>
                        <processingId>
                            <systemId>CoreCustomer-DCA</systemId>
                        </processingId>
                    </systemNotifications>

                </cmdNotifications>
            </exception>
        </NS2:retrievePrimaryCustomerForArrResponse>
    </NS1:Body>
</NS1:Envelope>


--------------
static-response-> account-validation ->success-response.xml


<NS1:Envelope
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/"
        xmlns:NS1="http://schemas.xmlsoap.org/soap/envelope/">
   <NS1:Body>
      <NS2:validateArrangementForPaymentResponse
              xmlns:NS2="http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/">
         <response>
            <responseHeader>
               <responseId>
                  <systemId>ESP</systemId>
                  <transactionId>3flS1c3fdecbf61bad3e001f4e40720211216055128893h</transactionId>
               </responseId>
               <operatingBrand>UBR</operatingBrand>
               <refRequestIds>
                  <systemId>RequestID</systemId>
                  <transactionId>123456789</transactionId>
               </refRequestIds>
               <cmdType>Response</cmdType>
               <cmdStatus>Succeeded</cmdStatus>
               <cmdNotifications>
                  <returnCode>0</returnCode>
                  <category>Success</category>
                  <description>Success</description>
                  <systemNotifications>
                     <returnCode>0</returnCode>
                     <category>Success</category>
                     <description>Success</description>
                     <processingId>
                        <systemId>AccountDB</systemId>
                     </processingId>
                  </systemNotifications>
                  <systemNotifications>
                     <returnCode>0</returnCode>
                     <category>Success</category>
                     <description>Success</description>
                     <processingId>
                        <systemId>BPP</systemId>
                     </processingId>
                  </systemNotifications>
               </cmdNotifications>
            </responseHeader>
            <validatedArrangement>
               <isSubjectOf xsi:type="avfpto:AccountArrangementIdentifierAssessment_TO">
                  <modulusCheckStatus>
                     <schemeName>AccountArrangementIdentifierStatus</schemeName>
                     <codeValue>Passed</codeValue>
                  </modulusCheckStatus>
               </isSubjectOf>
               <isClassifiedBy>
                  <schemeName>AccountingCategory</schemeName>
                  <codeValue>SUSP</codeValue>
               </isClassifiedBy>
               <name>ZER DEZPJ R/I</name>
               <accountingUnits>
                  <status>
                     <schemeName>AccountingUnitStatus</schemeName>
                     <codeValue>Domestic - Unrestricted</codeValue>
                  </status>
               </accountingUnits>
               <managingOrganizationUnit>
                  <hasForName>
                     <nameText>BALLYCONNELL (A)</nameText>
                  </hasForName>
                  <parentOrganization>
                     <alternativeIdentifier>
                        <identifier>980</identifier>
                        <context>
                           <schemeName>OrganizationEnterpriseIdType</schemeName>
                           <codeValue>BankIdentifier</codeValue>
                        </context>
                        <extendedProperties xsi:type="pdt:Property">
                           <string>ULSTER BANK IRL DAC</string>
                           <name>BankShortName</name>
                        </extendedProperties>
                     </alternativeIdentifier>
                     <hasForName>
                        <nameText>ULSTER BANK IRELAND DAC</nameText>
                     </hasForName>
                     <parentOrganization>
                        <alternativeIdentifier>
                           <identifier>K</identifier>
                           <context>
                              <schemeName>OrganizationEnterpriseIdType</schemeName>
                              <codeValue>InstanceIdentifier</codeValue>
                           </context>
                        </alternativeIdentifier>
                     </parentOrganization>
                  </parentOrganization>
                  <sortCodeRegistration>
                     <extendedProperties>
                        <string>Q1</string>
                        <name>CausticSubsection</name>
                     </extendedProperties>
                     <extendedProperties>
                        <string>N</string>
                        <name>EuroSortcode</name>
                     </extendedProperties>
                     <lifeCycleStatus>
                        <status>
                           <schemeName>RegistrationLifecycleStatus</schemeName>
                           <codeValue>Effective</codeValue>
                        </status>
                     </lifeCycleStatus>
                     <isIssuedIn>
                        <universalUniqueIdentifier>
                           <identifier>Republic of Ireland</identifier>
                           <context>
                              <schemeName>GeographicAreaType</schemeName>
                              <codeValue>Region</codeValue>
                           </context>
                        </universalUniqueIdentifier>
                     </isIssuedIn>
                     <isTrainingBranch>false</isTrainingBranch>
                     <sortCodeRegistrationType>
                        <schemeName>SortCodeRegistrationType</schemeName>
                        <codeValue>None</codeValue>
                     </sortCodeRegistrationType>
                     <paymentServicesProviderType>
                        <schemeName>PaymentServicesProviderType</schemeName>
                        <codeValue>Internal</codeValue>
                     </paymentServicesProviderType>
                     <agencyIndicator>N</agencyIndicator>
                     <activeIndicator>A</activeIndicator>
                     <nonFPSettlementSortCode>0</nonFPSettlementSortCode>
                     <nonFPSettlementAccountNumber>0</nonFPSettlementAccountNumber>
                     <isCreditCardHOCA>false</isCreditCardHOCA>
                     <FPSettlementSortCode>0</FPSettlementSortCode>
                     <FPSettlementAccountNumber>0</FPSettlementAccountNumber>
                     <FPSettlementType>N</FPSettlementType>
                     <isFPEnabled>N</isFPEnabled>
                     <isInternalFunction>false</isInternalFunction>
                  </sortCodeRegistration>
               </managingOrganizationUnit>
               <switchingArrangement>
                  <switchingStatus>
                     <schemeName>AccountArrangementSwitchingStatus</schemeName>
                     <codeValue>Not Switching</codeValue>
                  </switchingStatus>
               </switchingArrangement>
               <isBasedOnProduct>
                  <identifier>90</identifier>
                  <context>
                     <schemeName>ProductEnterpriseIdType</schemeName>
                     <codeValue>ProductIdentifier</codeValue>
                  </context>
               </isBasedOnProduct>
               <currency>
                  <alphabeticCode>
                     <schemeName>CurrencyType</schemeName>
                     <codeValue>EUR</codeValue>
                  </alphabeticCode>
               </currency>
            </validatedArrangement>
         </response>
      </NS2:validateArrangementForPaymentResponse>
   </NS1:Body>
</NS1:Envelope>

---------------------------
static-response-> customer-retrieval ->success-response.xml


<NS1:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:NS1="http://schemas.xmlsoap.org/soap/envelope/">
    <NS1:Body>
        <NS2:retrievePrimaryCustomerForArrResponse xmlns:NS2="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/">
            <response>
                <responseHeader>
                    <responseId>
                        <systemId>ESP</systemId>
                        <transactionId>5flS3ea4afb796849ac891220d25320250611171921910h</transactionId>
                    </responseId>
                    <operatingBrand>NWB</operatingBrand>
                    <refRequestIds>
                        <systemId>RequestID</systemId>
                        <transactionId>123456789</transactionId>
                    </refRequestIds>
                    <refRequestIds>
                        <systemId>SourceID</systemId>
                        <transactionId>ISO</transactionId>
                    </refRequestIds>
                    <cmdType>Response</cmdType>
                    <cmdStatus>Succeeded</cmdStatus>
                    <cmdNotifications>
                        <returnCode>0</returnCode>
                        <category>Success</category>
                        <description>Success</description>
                        <systemNotifications>
                            <returnCode>0</returnCode>
                            <category>Success</category>
                            <description>Success</description>
                            <processingId>
                                <systemId>CoreCustomer-DCA</systemId>
                            </processingId>
                        </systemNotifications>
                    </cmdNotifications>
                </responseHeader>
                <customer xsi:type="crfpTO:Organization_TO">
                    <universalUniqueIdentifier>
                        <identifier>1831187244</identifier>
                        <context>
                            <schemeName>CustomerEnterpriseIdType</schemeName>
                            <codeValue>BusinessIdentificationNumber</codeValue>
                        </context>
                    </universalUniqueIdentifier>
                    <isClassifiedBy xsi:type="crfpTO:ClassificationValue_TO">
                        <codeValue>W</codeValue>
                        <name>CustomerSegment</name>
                    </isClassifiedBy>
                    <hasForContactPreference>
                        <contactPoint xsi:type="crfpTO:PostalAddress_TO">
                            <usage>
                                <schemeName>ContactPointUsage</schemeName>
                                <codeValue>StatementAddress</codeValue>
                            </usage>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddresseeLine1</codeValue>
                                <address>VYXTZMNDILBJUWC AQFV</address>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddresseeLine2</codeValue>
                                <address>PJPX XNTJ GFR</address>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddressLine1</codeValue>
                                <address>TIWHPYOBBAC HDLJC</address>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddressLine2</codeValue>
                                <address>GZFVCZ DMWDE</address>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddressLine3</codeValue>
                                <address>WYKIQZ</address>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddressLine4</codeValue>
                                <address/>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>AddressLine5</codeValue>
                                <address/>
                            </hasComponent>
                            <hasComponent>
                                <schemeName>PostalAddressComponentType</schemeName>
                                <codeValue>PostCode</codeValue>
                                <address>DH7  6LD</address>
                            </hasComponent>
                            <postalCodeExemptionReason>
                                <schemeName>PostalCodeExemptionReasonType</schemeName>
                                <codeValue></codeValue>
                            </postalCodeExemptionReason>
                        </contactPoint>
                    </hasForContactPreference>
                    <hasForName xsi:type="crfpTO:InvolvedPartyName_TO">
                        <nameText>PJPX XNTJ GFR</nameText>
                        <usage>
                            <schemeName>InvolvedPartyNameType</schemeName>
                            <codeValue>CompanyName</codeValue>
                        </usage>
                    </hasForName>
                    <isSensitive>false</isSensitive>
                    <hasLegalAddress>
                        <hasComponent>
                            <schemeName>PostalAddressComponentType</schemeName>
                            <codeValue>AddressLine1</codeValue>
                            <address>TIWHPYOBBAC HDLJC</address>
                        </hasComponent>
                        <hasComponent>
                            <schemeName>PostalAddressComponentType</schemeName>
                            <codeValue>AddressLine2</codeValue>
                            <address>GZFVCZ DMWDE</address>
                        </hasComponent>
                        <hasComponent>
                            <schemeName>PostalAddressComponentType</schemeName>
                            <codeValue>AddressLine3</codeValue>
                            <address>WYKIQZ</address>
                        </hasComponent>
                        <hasComponent>
                            <schemeName>PostalAddressComponentType</schemeName>
                            <codeValue>AddressLine4</codeValue>
                            <address/>
                        </hasComponent>
                        <hasComponent>
                            <schemeName>PostalAddressComponentType</schemeName>
                            <codeValue>AddressLine5</codeValue>
                            <address/>
                        </hasComponent>
                        <hasComponent>
                            <schemeName>PostalAddressComponentType</schemeName>
                            <codeValue>PostalCode</codeValue>
                            <address>DH7  6LD</address>
                        </hasComponent>
                        <postalCodeExemptionReason>
                            <schemeName>PostalCodeExemptionReasonType</schemeName>
                            <codeValue></codeValue>
                        </postalCodeExemptionReason>
                    </hasLegalAddress>
                    <hasPartyType>
                        <schemeName>InvolvedPartyType</schemeName>
                        <codeValue>Organisation</codeValue>
                    </hasPartyType>
                    <hasInvolvedPartyAssociation>
                        <associatedInvolvedParty xsi:type="crfpTO:Individual_TO">
                            <hasForName xsi:type="crfpTO:IndividualName_TO">
                                <middleNames/>
                                <prefixTitle>
                                    <schemeName>IndividualNamePrefixType</schemeName>
                                    <codeValue>MRS</codeValue>
                                </prefixTitle>
                                <firstName>EXJPF</firstName>
                                <lastName>HLPCUZAACT</lastName>
                            </hasForName>
                        </associatedInvolvedParty>
                        <associationType>
                            <schemeName>InvolvedPartyAssociationType</schemeName>
                            <codeValue>Contact</codeValue>
                        </associationType>
                    </hasInvolvedPartyAssociation>
                    <residesAt>
                        <schemeName>CountryCode</schemeName>
                        <codeValue>GBR</codeValue>
                    </residesAt>
                </customer>
            </response>
        </NS2:retrievePrimaryCustomerForArrResponse>
    </NS1:Body>
</NS1:Envelope>



---------------------------------------------------

Test Classes:-


package com.rbs.bdd.application.awsconfig;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
public class AwsSecretManagerConfigTest {
    @InjectMocks
    private AwsSecretManagerConfig awsSecretManagerConfig;
    @Mock
    private SecretsManagerClient mockSecretsManagerClient;

    @Mock
    private GetSecretValueResponse mockResponse;



    private static final String TEST_USER = "test_user";
    private static final String TEST_PASS = "test_password";
    private static final String TEST_DBNAME = "test_dbname";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String DBNAME = "dbname";

    public final String mockSecretJson = "{\n" +
            "\""+USERNAME+"\": \""+TEST_USER+"\",\n" +
            "\""+PASSWORD+"\": \""+TEST_PASS+"\",\n" +
            "\""+DBNAME+"\": \""+TEST_DBNAME+"\" \n" +
            "}";

     @Test
    public void testSecretsManagerClientBean(){

        SecretsManagerClient mockSecretsManagerClient = mock(SecretsManagerClient.class);

        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId("my-secret").build();
        GetSecretValueResponse  mockResponse = Mockito.mock(GetSecretValueResponse.class);
        Mockito.when(mockSecretsManagerClient.getSecretValue(Mockito.eq(request))).thenReturn(mockResponse);

         SdkHttpResponse sdkHttpResponseMock = Mockito.mock(SdkHttpResponse.class);
         Mockito.when(sdkHttpResponseMock.isSuccessful()).thenReturn(true);
         Mockito.when(mockResponse.sdkHttpResponse()).thenReturn(sdkHttpResponseMock);
         Mockito.when(mockResponse.secretString()).thenReturn(mockSecretJson);

        try(MockedStatic<SecretsManagerClient> mockedStatic = mockStatic(SecretsManagerClient.class)){
            SecretsManagerClientBuilder builderMock = mock(SecretsManagerClientBuilder.class);


            mockedStatic.when(SecretsManagerClient::builder).thenReturn(builderMock);
            Mockito.when(builderMock.region(Region.of("us-east-1"))).thenReturn(builderMock);
            Mockito.when(builderMock.credentialsProvider(Mockito.any())).thenReturn(builderMock);
            Mockito.when(builderMock.build()).thenReturn(mockSecretsManagerClient);

            SecretsManagerClient client = awsSecretManagerConfig.secretsManagerClient("us-east-1","my-secret");
            assertNotNull(client);
            Mockito.verify(mockSecretsManagerClient).getSecretValue(request);
        }
    }

    @Test
    public void testSecretsManagerClientBeanWhenUnableToGetSecret(){

        SecretsManagerClient mockSecretsManagerClient = mock(SecretsManagerClient.class);

        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId("my-secret").build();
        GetSecretValueResponse  mockResponse = Mockito.mock(GetSecretValueResponse.class);

        Mockito.when(mockSecretsManagerClient.getSecretValue(Mockito.eq(request))).thenReturn(mockResponse);
        Mockito.when(mockResponse.secretString()).thenReturn(mockSecretJson);

        SdkHttpResponse sdkHttpResponseMock = Mockito.mock(SdkHttpResponse.class);
        Mockito.when(sdkHttpResponseMock.isSuccessful()).thenReturn(true);
        Mockito.when(mockResponse.sdkHttpResponse()).thenReturn(sdkHttpResponseMock);

        try(MockedStatic<SecretsManagerClient> mockedStatic = mockStatic(SecretsManagerClient.class)){
            SecretsManagerClientBuilder builderMock = mock(SecretsManagerClientBuilder.class);

            mockedStatic.when(SecretsManagerClient::builder).thenReturn(builderMock);
            Mockito.when(builderMock.region(Region.of("us-east-1"))).thenReturn(builderMock);
            Mockito.when(builderMock.credentialsProvider(Mockito.any())).thenReturn(builderMock);
            Mockito.when(builderMock.build()).thenReturn(mockSecretsManagerClient);

            AwsSecretManagerConfig awsSecretManagerConfig = new AwsSecretManagerConfig();
            SecretsManagerClient client = awsSecretManagerConfig.secretsManagerClient("us-east-1","my-secret");

            assertNotNull(client);
            Mockito.verify(mockSecretsManagerClient).getSecretValue(request);

        }
    }





}


----
package com.rbs.bdd.application.awsconfig;

import com.fasterxml.jackson.databind.ObjectMapper;
import liquibase.integration.spring.SpringLiquibase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import javax.sql.DataSource;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DatabaseConfigTest {
    @Mock
    private SecretsManagerClient secretsManagerClient;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private DatabaseConfig databaseConfig;

    @BeforeEach
    void setup(){
        MockitoAnnotations.openMocks(this);
    }

@Test
    public void testDataSourceIsCreatedFromSecrets() throws Exception{

        String mockSecretJson = """
            {
            "username":"test_username",
            "password":"test_password",
            "dbname":"test_dbname"
            }
            """;
        SdkHttpResponse httpResponse = mock(SdkHttpResponse.class);
        when(httpResponse.isSuccessful()).thenReturn(true);

        GetSecretValueResponse secretValueResponse = mock(GetSecretValueResponse.class);
        when(secretValueResponse.secretString()).thenReturn(mockSecretJson);
        when(secretValueResponse.sdkHttpResponse()).thenReturn(httpResponse);

        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(secretValueResponse);

        DataSource datasource = databaseConfig.dataSource();

        assertNotNull(datasource);
        SpringLiquibase springLiquibase = databaseConfig.SpringLiquibase();
        assertNotNull(springLiquibase);

    }


    @Test
    public void testDataSourceProperties(){
        assertNotNull(databaseConfig.dataSourceProperties());
    }





}


---
package com.rbs.bdd.application.service;

import com.rbs.bdd.application.exception.AccountValidationException;
import com.rbs.bdd.domain.enums.ServiceConstants;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPBody;
import jakarta.xml.soap.SOAPMessage;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.w3c.dom.Document;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.rbs.bdd.domain.enums.ServiceConstants.Paths.ACCOUNT_VALIDATION_REQUEST;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test suite for {@link AccountValidationService} which validates both successful
 * and error response scenarios based on incoming SOAP request data.
 *
 * This test uses a static SOAP XML template loaded and modified at runtime,
 * and verifies the final response structure using DOM + XPath assertions.
 */
@Slf4j

class AccountValidationServiceTest {

    private AccountValidationService accountValidationService;

    /**
     * Initializes the test with a fresh instance of {@link AccountValidationService}.
     */
    @BeforeEach
    void setup() {
        accountValidationService = new AccountValidationService();
    }

    /**
     * Loads the SOAP request XML from a template file, replaces placeholder variables,
     * and unmarshals only the payload into a {@link ValidateArrangementForPaymentRequest} object.
     *
     * @param identifier the IBAN or UBAN
     * @param codeValue the account code value type
     * @return deserialized Java request object
     * @throws Exception in case of JAXB or file issues
     */
    private ValidateArrangementForPaymentRequest loadRequest(String identifier, String codeValue) throws Exception {
        String template = Files.readString(Path.of(ACCOUNT_VALIDATION_REQUEST));
        String finalXml = template
                .replace("${IDENTIFIER}", identifier)
                .replace("${CODEVALUE}", codeValue);

        SOAPMessage soapMessage = MessageFactory.newInstance()
                .createMessage(null, new ByteArrayInputStream(finalXml.getBytes(StandardCharsets.UTF_8)));
        SOAPBody body = soapMessage.getSOAPBody();

        JAXBContext jaxbContext = JAXBContext.newInstance(ValidateArrangementForPaymentRequest.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        JAXBElement<ValidateArrangementForPaymentRequest> jaxbElement =
                unmarshaller.unmarshal(body.getElementsByTagNameNS("*", "validateArrangementForPayment").item(0),
                        ValidateArrangementForPaymentRequest.class);

        return jaxbElement.getValue();
    }

    /**
     * Invokes the SOAP validation service with the given request and returns the
     * transformed SOAP response as a DOM document.
     *
     * @param request validated SOAP request
     * @return DOM document of modified response
     * @throws Exception in case of failure
     */
    private Document invokeServiceAndGetModifiedDoc(ValidateArrangementForPaymentRequest request) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        WebServiceMessage message = new SaajSoapMessage(MessageFactory.newInstance().createMessage());
        accountValidationService.validateSchema(request);
        accountValidationService.validateBusinessRules(request, message);
        message.writeTo(outputStream);

        return DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new ByteArrayInputStream(outputStream.toByteArray()));
    }

    /**
     * Evaluates and returns the XPath value from the given DOM document.
     *
     * @param doc the DOM document
     * @param expression the XPath expression
     * @return extracted value
     * @throws Exception if XPath fails
     */
    private String getXpathValue(Document doc, String expression) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate(expression, doc);
    }

    /**
     * Validates success response for IBAN_1 with expected values:
     * Restricted status, Switched, Modulus Passed.
     */
    @Test
    @DisplayName("Success Response for IBAN_1 - Domestic Restricted, Switched, Modulus Passed")
    void testIBAN1_SuccessResponse() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("60161331926801", "UKBasicBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);

        log.debug("=== Full SOAP Response ===");
        log.debug("Success Response for IBAN_1 - Domestic Restricted, Switched, Modulus Passed");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");

        String XPATH_ACCOUNT_STATUS = "//*[local-name()='accountingUnits']/*[local-name()='status']/*[local-name()='codeValue']";
        String XPATH_SWITCHING_STATUS = "//*[local-name()='switchingStatus']/*[local-name()='codeValue']";
        String XPATH_MODULUS_STATUS = "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']";


        assertEquals("Domestic - Restricted", getXpathValue(doc, "//*[local-name()='accountingUnits']/*[local-name()='status']"));
        assertEquals("Switched", getXpathValue(doc, "//*[local-name()='switchingStatus']"));
        assertEquals("Passed", getXpathValue(doc, "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']"));

    }

    /**
     * Validates success response for IBAN_2 with expected values:
     * Restricted status, Not Switching, Modulus Passed.
     */
    @Test
    @DisplayName("Success Response for IBAN_2 - Domestic Restricted, Not Switching, Modulus Passed")
    void testIBAN2_SuccessResponse() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("12345698765437", "UKBasicBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("=== Full SOAP Response ===");
        log.debug("Success Response for IBAN_2 - Domestic Restricted, Not Switching, Modulus Passed");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("Domestic - Restricted", getXpathValue(doc, "//*[local-name()='accountingUnits']/*[local-name()='status']"));
        assertEquals("Not Switching", getXpathValue(doc, "//*[local-name()='switchingStatus']"));
        assertEquals("Passed", getXpathValue(doc, "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']"));
    }

    /**
     * Validates success response for IBAN_3 with expected values:
     * Unrestricted status, Switched, Modulus Passed.
     */
    @Test
    @DisplayName("Success Response for IBAN_3 - Domestic Unrestricted, Switched, Modulus Passed")
    void testIBAN3_SuccessResponse() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("10201530093422", "UKBasicBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("=== Full SOAP Response ===");
        log.debug("Success Response for IBAN_3 - Domestic Unrestricted, Switched, Modulus Passed");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("Domestic - Unrestricted",getXpathValue(doc, "//*[local-name()='accountingUnits']/*[local-name()='status']"));
        assertEquals("Switched", getXpathValue(doc, "//*[local-name()='switchingStatus']"));
        assertEquals("Passed", getXpathValue(doc, "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']"));
    }

    /**
     * Validates success response for IBAN_4 with expected values:
     * Unrestricted status, Not Switching, Modulus Failed.
     */
    @Test
    @DisplayName("Success Response for IBAN_4 - Domestic Unrestricted, Not Switching, Modulus Failed")
    void testIBAN4_SuccessResponse() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("20201555555567", "UKBasicBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("=== Full SOAP Response ===");
        log.debug("Return Success Response for IBAN_4 - Domestic Unrestricted, Not Switching, Modulus Failed");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("Domestic - Unrestricted", getXpathValue(doc, "//*[local-name()='accountingUnits']/*[local-name()='status']"));
        assertEquals("Not Switching", getXpathValue(doc, "//*[local-name()='switchingStatus']"));
        assertEquals("Failed", getXpathValue(doc, "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']"));
    }

    /**
     * Validates error response for unmatched IBAN.
     */
    @Test
    @DisplayName("Should return error when IBAN does not match any account")
    void testNoMatch_MOD97Failure() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("GB94BARC10201530093420", "InternationalBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("Return error when IBAN does not match any account");
        log.debug("=== Full SOAP Response ===");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("MOD97 failure for the IBAN", getXpathValue(doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC));
        assertEquals("Failed", getXpathValue(doc, "//*[local-name()='cmdStatus']"));
    }

    /**
     * Validates error response for IBAN with invalid length.
     */
    @Test
    @DisplayName("Should return error for invalid IBAN length")
    void testInvalidIbanLength() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("GB123", "InternationalBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("Return error for invalid IBAN length");
        log.debug("=== Full SOAP Response ===");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("Length of IBAN is Invalid", getXpathValue(doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC));
    }

    /**
     * Validates error response for UBAN with invalid length.
     */
    @Test
    @DisplayName("Should return error for invalid UBAN length")
    void testInvalidUbanLength() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("123456", "UKBasicBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);

        log.debug("Return error for invalid UBAN length:- ");
        log.debug("=== Full SOAP Response ===");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("100||INVALID SORT CODE OR ISSUING AUTH ID PASSED||Execution Successful", getXpathValue(doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC));
    }

    /**
     * Validates DB2 SQL error response when GB-prefixed UBAN is used.
     */
    @Test
    @DisplayName("Should return DB2 SQL error for GB UBAN")
    void testDb2ErrorForGBUban() throws Exception {
        String error="Service operation validateArrangementForPayment failed due to an error in the ESP. Contact systems management to resolve the problem";
        ValidateArrangementForPaymentRequest req = loadRequest("GB12345678901234", "UKBasicBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("Return DB2 SQL error for GB UBAN");
        log.debug("=== Full SOAP Response ===");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertTrue(getXpathValue(doc, ServiceConstants.XPath.XPATH_CMD_DESCRIPTION).contains(error));
    }

    /**
     * Validates country code error when IBAN does not start with GB.
     */
    @Test
    @DisplayName("Should return country code error when IBAN does not start with GB")
    void testWrongCountryCode() throws Exception {
        ValidateArrangementForPaymentRequest req = loadRequest("FR1234567890123456789012", "InternationalBankAccountNumber");
        Document doc = invokeServiceAndGetModifiedDoc(req);
        log.debug("Return country code error when IBAN does not start with GB ");
        log.debug("=== Full SOAP Response ===");
        StringWriter writer= new StringWriter();
        javax.xml.transform.TransformerFactory.newInstance()
                .newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(doc),
                        new javax.xml.transform.stream.StreamResult(writer));
        log.debug("Response is :  "+writer.toString());
        log.debug("===========================");
        assertEquals("SYSTEM_ERROR,incidentID=1f2ff299-9d93-41a5-9119-b4a552f0191e", getXpathValue(doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC));
    }
}


---
package com.rbs.bdd.application.service;

import com.rbs.bdd.application.port.out.RetrieveCustomerPort;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ws.WebServiceMessage;

import static org.mockito.Mockito.*;

class CustomerRetrievalOrchestratorTest {

    private RetrieveCustomerPort retrieveCustomerPort;
    private CustomerRetrievalOrchestrator orchestrator;
    private RetrievePrimaryCustomerForArrRequest mockRequest;
    private WebServiceMessage mockMessage;

    @BeforeEach
    void setUp() {
        retrieveCustomerPort = mock(RetrieveCustomerPort.class);
        orchestrator = new CustomerRetrievalOrchestrator(retrieveCustomerPort);
        mockRequest = mock(RetrievePrimaryCustomerForArrRequest.class);
        mockMessage = mock(WebServiceMessage.class);
    }

    @Test
    void validateCustomerRetrieval_shouldDelegateToPorts() {
        // Act
        orchestrator.validateCustomerRetrieval(mockRequest, mockMessage);

        // Assert
        verify(retrieveCustomerPort).validateSchema(mockRequest);
        verify(retrieveCustomerPort).retrieveCustomer(mockRequest, mockMessage);
    }
}

---
package com.rbs.bdd.application.service;
import com.rbs.bdd.domain.enums.ErrorConstants;
import com.rbs.bdd.infrastructure.repository.CustomerRepository;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPBody;
import jakarta.xml.soap.SOAPMessage;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.rbs.bdd.domain.enums.ServiceConstants.Paths.CUSTOMER_RETRIEVAL_REQUEST;
import static com.rbs.bdd.domain.enums.ServiceConstants.XPath.*;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j

class CustomerRetrievalServiceTest {

    private CustomerRetrievalService service;
    private CustomerRepository mockRepository;

    @BeforeEach
    void setup() {
        mockRepository= Mockito.mock(CustomerRepository.class);
        service = new CustomerRetrievalService(mockRepository);
    }

    private RetrievePrimaryCustomerForArrRequest loadRequest(String identifier, String codeValue) throws Exception {
        String template = Files.readString(Path.of(CUSTOMER_RETRIEVAL_REQUEST));
        String finalXml = template.replace("${IDENTIFIER}", identifier).replace("${CODEVALUE}", codeValue);

        SOAPMessage soapMessage = MessageFactory.newInstance()
                .createMessage(null, new ByteArrayInputStream(finalXml.getBytes(StandardCharsets.UTF_8)));
        SOAPBody body = soapMessage.getSOAPBody();

        JAXBContext context = JAXBContext.newInstance(RetrievePrimaryCustomerForArrRequest.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        JAXBElement<RetrievePrimaryCustomerForArrRequest> root =
                unmarshaller.unmarshal(body.getElementsByTagNameNS("*", "retrievePrimaryCustomerForArr").item(0),
                        RetrievePrimaryCustomerForArrRequest.class);

        return root.getValue();
    }

    private Document invokeAndGetResponse(RetrievePrimaryCustomerForArrRequest request) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        WebServiceMessage message = new SaajSoapMessage(MessageFactory.newInstance().createMessage());

        service.validateSchema(request);
        service.retrieveCustomer(request, message);
        message.writeTo(outputStream);

        return DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new ByteArrayInputStream(outputStream.toByteArray()));
    }

    private String getXpath(Document doc, String expression) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate(expression, doc);
    }

    @Test
    @DisplayName("Success: Valid customer IBAN should populate name fields")
    void testValidCustomerResponse() throws Exception {
        RetrievePrimaryCustomerForArrRequest request = loadRequest("GB29NWBK60161331926801", "InternationalBankAccountNumber");
        Document doc = invokeAndGetResponse(request);
        assertEquals("Alice", getXpath(doc, XPATH_FIRST_NAME));
        assertEquals("Johnson", getXpath(doc, XPATH_LAST_NAME));
        assertEquals("MR", getXpath(doc, XPATH_PREFIX_TYPE));
    }

    @Test
    @DisplayName("Error: UBAN with GB prefix returns ERR_UBAN_GB")
    void testGbPrefixedUban() throws Exception {
        RetrievePrimaryCustomerForArrRequest request = loadRequest("GB12345678901234", "UKBasicBankAccountNumber");
        Document doc = invokeAndGetResponse(request);
        assertEquals(ErrorConstants.ERR_UBAN_GB.detail().description(), getXpath(doc, XPATH_CMD_DESCRIPTION));
    }

    @Test
    @DisplayName("Error: UBAN with invalid length returns Customer Not Found")
    void testInvalidUbanLength() throws Exception {
        RetrievePrimaryCustomerForArrRequest request = loadRequest("123456", "UKBasicBankAccountNumber");
        Document doc = invokeAndGetResponse(request);
        assertEquals("Unable to Complete Request", getXpath(doc, XPATH_CMD_DESCRIPTION));
    }

    @Test
    @DisplayName("Error: Unmatched UBAN triggers Customer Not Found")
    void testUbanMod97Failure() throws Exception {
        RetrievePrimaryCustomerForArrRequest request = loadRequest("99999999999999", "UKBasicBankAccountNumber");
        Document doc = invokeAndGetResponse(request);
        assertEquals("Unable to Complete Request", getXpath(doc, XPATH_CMD_DESCRIPTION));
    }


    @Test
    @DisplayName("Error: IBAN does not match any customer")
    void testUnmatchedIban() throws Exception {
        RetrievePrimaryCustomerForArrRequest request = loadRequest("GB29NWBK60161300000000", "InternationalBankAccountNumber");
        Document doc = invokeAndGetResponse(request);
        assertEquals("Unable to Complete Request", getXpath(doc, XPATH_CMD_DESCRIPTION));

    }
}

---
package com.rbs.bdd.application.service;

import com.rbs.bdd.application.port.out.AccountValidationPort;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ws.WebServiceMessage;

import static org.mockito.Mockito.*;

class PaymentOrchestratorTest {

    private AccountValidationPort accountValidationPort;
    private AccountValidationOrchestrator orchestrator;
    private ValidateArrangementForPaymentRequest mockRequest;
    private WebServiceMessage mockMessage;

    @BeforeEach
    void setUp() {
        accountValidationPort = mock(AccountValidationPort.class);
        orchestrator = new AccountValidationOrchestrator(accountValidationPort);
        mockRequest = mock(ValidateArrangementForPaymentRequest.class);
        mockMessage = mock(WebServiceMessage.class);
    }

    @Test
    void validateArrangementForPayment_shouldDelegateToPorts() {
        // Act
        orchestrator.validateArrangementForPayment(mockRequest, mockMessage);

        // Assert
        verify(accountValidationPort).validateSchema(mockRequest);
        verify(accountValidationPort).validateBusinessRules(mockRequest, mockMessage);
    }
}



---------
package com.rbs.bdd.infrastructure.soap.api;

import com.rbs.bdd.application.port.in.CustomerRetrievalPort;
import com.rbs.bdd.application.port.in.PaymentValidationPort;
import com.rbsg.soa.c040paymentmanagement.arrvalidationforpayment.v01.ValidateArrangementForPaymentRequest;
import com.rbsg.soa.c040paymentmanagement.customerretrievalforpayment.v01.RetrievePrimaryCustomerForArrRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;

import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link PaymentValidationSoapAdapter}, which handles SOAP requests
 * for account validation and customer retrieval.
 */
class PaymentValidationSoapAdapterTest {

    private PaymentValidationPort paymentValidationPort;
    private CustomerRetrievalPort customerRetrievalPort;
    private PaymentValidationSoapAdapter adapter;
    private MessageContext mockContext;
    private WebServiceMessage mockResponse;

    /**
     * Sets up the required mocks before each test.
     */
    @BeforeEach
    void setUp() {
        paymentValidationPort = mock(PaymentValidationPort.class);
        customerRetrievalPort = mock(CustomerRetrievalPort.class);
        adapter = new PaymentValidationSoapAdapter(paymentValidationPort, customerRetrievalPort);

        mockContext = mock(MessageContext.class);
        mockResponse = mock(WebServiceMessage.class);

        when(mockContext.getResponse()).thenReturn(mockResponse);
    }

    /**
     * Tests that the `validateArrangementForPayment` method delegates the request
     * to the paymentValidationPort with the correct arguments.
     */
    @Test
    void testValidateArrangementForPaymentDelegatesToPort() {
        ValidateArrangementForPaymentRequest request = new ValidateArrangementForPaymentRequest();

        adapter.validateArrangementForPayment(request, mockContext);

        verify(paymentValidationPort, times(1)).validateArrangementForPayment(eq(request), eq(mockResponse));
    }

    /**
     * Tests that the `validateCustomerRetrieval` method delegates the request
     * to the customerRetrievalPort with the correct arguments.
     */
    @Test
    void testValidateCustomerRetrievalDelegatesToPort() {
        RetrievePrimaryCustomerForArrRequest request = new RetrievePrimaryCustomerForArrRequest();

        adapter.validateCustomerRetrieval(request, mockContext);

        verify(customerRetrievalPort, times(1)).validateCustomerRetrieval(eq(request), eq(mockResponse));
    }
}


-----
package com.rbs.bdd.infrastructure.soap.interceptor;

import com.rbs.bdd.domain.enums.ServiceConstants;
import com.rbs.bdd.util.SoapInterceptorUtils;
import jakarta.xml.soap.MessageFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.springframework.ws.soap.server.endpoint.interceptor.PayloadValidatingInterceptor;
import org.xml.sax.SAXParseException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class AccountSchemaValidationInterceptorTest {

    private AccountSchemaValidationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new AccountSchemaValidationInterceptor();
    }

    /**
     * Test custom schema validation error handling response.
     */
    @Test
    void testHandleSchemaValidationFailure_customResponse() throws Exception {
        String dummyXml = """
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
              <soapenv:Body>
                <testRequest></testRequest>
              </soapenv:Body>
            </soapenv:Envelope>
            """;

        WebServiceMessage request = new SaajSoapMessage(
                MessageFactory.newInstance().createMessage(null,
                        new ByteArrayInputStream(dummyXml.getBytes()))
        );

        MessageContext messageContext = mock(MessageContext.class);
        when(messageContext.getRequest()).thenReturn(request);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest, servletResponse));

        boolean result = interceptor.handleRequestValidationErrors(messageContext, new SAXParseException[] {});
        assertFalse(result);

        String response = servletResponse.getContentAsString();
        assertTrue(response.contains("transactionId")); // ensure transformation
        assertEquals(500, servletResponse.getStatus());
    }

    /**
     * Test interceptor skips request if namespace doesn't match.
     */
    @Test
    void testHandleRequest_skipsInterceptorIfNamespaceMismatch() throws Exception {
        MessageContext messageContext = mock(MessageContext.class);

        try (MockedStatic<SoapInterceptorUtils> mockedUtils = mockStatic(SoapInterceptorUtils.class)) {
            mockedUtils.when(() ->
                            SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(any(), any()))
                    .thenReturn(true);

            boolean result = interceptor.handleRequest(messageContext, new Object());

            assertTrue(result);
            mockedUtils.verify(() ->
                    SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(messageContext,
                            ServiceConstants.Namespaces.NAMESPACE_URI_FOR_ACCOUNT_VALIDATION));
        }
    }



    /**
     * Tests the protected method for loading a resource stream.
     */
    @Test
    void testGetClassLoaderResource_shouldReturnStream() {
        InputStream stream = interceptor.getClassLoaderResource("static-request/account-validation-request.xml"); // Any known file on classpath
        assertNotNull(stream);
    }
}



---
package com.rbs.bdd.infrastructure.soap.interceptor;


        import com.rbs.bdd.application.exception.SchemaValidationException;
        import com.rbs.bdd.domain.enums.ServiceConstants;
        import com.rbs.bdd.util.SoapInterceptorUtils;
        import jakarta.xml.soap.MessageFactory;
        import lombok.extern.slf4j.Slf4j;
        import org.junit.jupiter.api.BeforeEach;
        import org.junit.jupiter.api.DisplayName;
        import org.junit.jupiter.api.Test;
        import org.mockito.MockedStatic;
        import org.springframework.mock.web.MockHttpServletRequest;
        import org.springframework.mock.web.MockHttpServletResponse;
        import org.springframework.web.context.request.RequestContextHolder;
        import org.springframework.web.context.request.ServletRequestAttributes;
        import org.springframework.ws.WebServiceMessage;
        import org.springframework.ws.context.MessageContext;
        import org.springframework.ws.soap.saaj.SaajSoapMessage;
        import org.w3c.dom.Document;
        import org.w3c.dom.NodeList;
        import org.xml.sax.SAXParseException;

        import javax.xml.parsers.DocumentBuilderFactory;
        import java.io.ByteArrayInputStream;
        import java.io.ByteArrayOutputStream;
        import java.io.InputStream;

        import static org.junit.jupiter.api.Assertions.*;
        import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link CustomerRetrievalSchemaValidationInterceptorTest}, ensuring schema validation errors
 * are intercepted and custom static error SOAP responses are returned with dynamic field replacements.
 */

@Slf4j
class CustomerRetrievalSchemaValidationInterceptorTest {

    private CustomerSchemaValidationInterceptor interceptor;

    @BeforeEach
    void setup() {
        interceptor = new CustomerSchemaValidationInterceptor();
    }

    /**
     * Tests that a custom SOAP fault is returned with HTTP 500 when schema validation fails.
     */
    @Test
    @DisplayName("Should return custom error XML response with replaced transactionId and timestamp")
    void testHandleRequestValidationErrors_customFaultReturned() throws Exception {
        // Arrange: Load request XML that includes transactionId and systemId
        InputStream requestXml = getClass().getClassLoader().getResourceAsStream("static-request/customer-retrieval-request.xml");
        assertNotNull(requestXml);

        ByteArrayOutputStream requestOut = new ByteArrayOutputStream();
        requestXml.transferTo(requestOut);

        WebServiceMessage webServiceMessage = new SaajSoapMessage(
                MessageFactory.newInstance().createMessage(null,
                        new ByteArrayInputStream(requestOut.toByteArray()))
        );

        MessageContext messageContext = mock(MessageContext.class);
        when(messageContext.getRequest()).thenReturn(webServiceMessage);

        // Mock HTTP response and Spring context
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest,servletResponse));

        // Act
        boolean result = interceptor.handleRequestValidationErrors(messageContext, new SAXParseException[]{});

        // Assert
        assertFalse(result); // false = custom SOAP sent successfully

        String responseContent = servletResponse.getContentAsString();
        log.debug("Actual response"+responseContent);
        assertTrue(responseContent.contains("<transactionId>"), "transactionId should be injected");
        assertTrue(responseContent.contains("<systemId>ESP</systemId>")); // use actual expected value from request
        assertEquals(500, servletResponse.getStatus());
    }

    /**
     * Tests that a SchemaValidationException is thrown when static XML is missing.
     */
    @Test
    @DisplayName("Should throw SchemaValidationException when error XML is not found")
    void testHandleRequestValidationErrors_missingStaticXml() {
        // Use subclass to override file loading behavior to simulate missing file
        AccountSchemaValidationInterceptor customInterceptor = new AccountSchemaValidationInterceptor() {
            @Override
            protected InputStream getClassLoaderResource(String path) {
                return null; // simulate missing file
            }
        };

        MessageContext messageContext = mock(MessageContext.class);
        when(messageContext.getRequest()).thenReturn(mock(WebServiceMessage.class));

        assertThrows(SchemaValidationException.class,
                () -> customInterceptor.handleRequestValidationErrors(messageContext, new SAXParseException[]{}));
    }

    /**
     * Tests that <refRequestIds> is removed if request doesn't contain requestIds.
     */
    @Test
    @DisplayName("Should remove <refRequestIds> if <requestIds> missing in request")
    void testRemoveRefRequestIds_whenRequestIdsMissing() throws Exception {
        // Arrange: request XML without transactionId/systemId
        String malformedXml = """
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                    <soapenv:Body>
                        <testRequest></testRequest>
                    </soapenv:Body>
                </soapenv:Envelope>
                """;

        WebServiceMessage message = new SaajSoapMessage(
                MessageFactory.newInstance().createMessage(null,
                        new ByteArrayInputStream(malformedXml.getBytes()))
        );

        MessageContext messageContext = mock(MessageContext.class);
        when(messageContext.getRequest()).thenReturn(message);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest,servletResponse));

        // Act
        boolean result = interceptor.handleRequestValidationErrors(messageContext, new SAXParseException[]{});

        // Assert
        assertFalse(result);
        Document responseDoc = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(new ByteArrayInputStream(servletResponse.getContentAsByteArray()));
        log.debug("Should remove <refRequestIds> if <requestIds> missing in request");
        NodeList refRequestIds = responseDoc.getElementsByTagNameNS("*", "refRequestIds");
        assertEquals(0, refRequestIds.getLength(), "refRequestIds should be removed");
    }

    /**
     * Test interceptor skips request if namespace doesn't match.
     */
    @Test
    void testHandleRequest_skipsInterceptorIfNamespaceMismatch() throws Exception {
        MessageContext messageContext = mock(MessageContext.class);

        try (MockedStatic<SoapInterceptorUtils> mockedUtils = mockStatic(SoapInterceptorUtils.class)) {
            mockedUtils.when(() ->
                            SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(any(), any()))
                    .thenReturn(true);

            boolean result = interceptor.handleRequest(messageContext, new Object());

            assertTrue(result);
            mockedUtils.verify(() ->
                    SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(messageContext,
                            ServiceConstants.Namespaces.NAMESPACE_URI_FOR_CUSTOMER_RETRIEVAL));
        }
    }


    /**
     * Tests the protected method for loading a resource stream.
     */
    @Test
    void testGetClassLoaderResource_shouldReturnStream() {
        InputStream stream = interceptor.getClassLoaderResource("static-request/customer-retrieval-request.xml"); // Any known file on classpath
        assertNotNull(stream);
    }
}


