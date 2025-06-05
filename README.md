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


--------------------

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
---------------
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

-----------------
package com.rbs.bdd.application.port.in;


import org.springframework.ws.WebServiceMessage;
import com.rbs.bdd.generated.ValidateArrangementForPaymentRequest;

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

-------------

package com.rbs.bdd.application.port.out;

import com.rbs.bdd.generated.ValidateArrangementForPaymentRequest;
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

package com.rbs.bdd.application.service;


import com.rbs.bdd.application.exception.AccountValidationException;
import com.rbs.bdd.application.port.out.AccountValidationPort;
import com.rbs.bdd.common.ErrorConstants;
import com.rbs.bdd.common.ServiceConstants;
import com.rbs.bdd.domain.enums.AccountStatus;
import com.rbs.bdd.domain.enums.ModulusCheckStatus;
import com.rbs.bdd.domain.enums.SwitchingStatus;
import com.rbs.bdd.domain.enums.model.ErrorDetail;
import com.rbs.bdd.generated.ValidateArrangementForPaymentRequest;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
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
import java.util.Optional;
import java.util.UUID;

import static com.rbs.bdd.common.ServiceConstants.*;
import static com.rbs.bdd.domain.enums.AccountStatus.DOMESTIC_RESTRICTED;
import static com.rbs.bdd.domain.enums.AccountStatus.DOMESTIC_UNRESTRICTED;
import static com.rbs.bdd.domain.enums.ModulusCheckStatus.FAILED;
import static com.rbs.bdd.domain.enums.ModulusCheckStatus.PASSED;
import static com.rbs.bdd.domain.enums.SwitchingStatus.NOT_SWITCHING;
import static com.rbs.bdd.domain.enums.SwitchingStatus.SWITCHED;

/**
 * Service responsible for validating SOAP requests for account validation and returning
 * static success or error responses based on configured rules.
 */
@Service
@RequiredArgsConstructor
public class AccountValidationService implements AccountValidationPort {

    private static final Logger logger = LoggerFactory.getLogger(AccountValidationService.class);

    /**
     * Logs the fact that schema validation is already handled by Spring WS.
     */
    @Override
    public void validateSchema(ValidateArrangementForPaymentRequest request) {
        logger.info("Schema validation completed by Spring WS");
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
            logger.info("Starting business rule validation for request.");
            RequestParams params = extractParams(request);
            XPath xpath = XPathFactory.newInstance().newXPath();
            Document responseDoc;

            Optional<ErrorDetail> error = determineError(params);
            if (error.isPresent()) {
                logger.info("Business error condition detected: {}", error.get().description);
                responseDoc = loadAndParseXml(ServiceConstants.ERROR_XML_PATH);
                applyErrorResponse(responseDoc, xpath, error.get(), params.originalTxnId);
            } else {
                Optional<ResponseConfig> config = determineMatchingConfig(params);
                if (config.isPresent()) {
                    logger.info("Matched account configuration: {}", config.get());
                    responseDoc = loadAndParseXml("static-response/response1.xml");
                    updateSuccessResponse(responseDoc, xpath, config.get(), params);
                } else {
                    logger.warn("No account matched. Returning MOD97 failure.");
                    responseDoc = loadAndParseXml(ServiceConstants.ERROR_XML_PATH);
                    applyErrorResponse(responseDoc, xpath, ErrorConstants.ERR_MOD97_IBAN, params.originalTxnId);
                }
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
           TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");
            Transformer transformer = transformerFactory.newTransformer();
            transformer.transform(new DOMSource(responseDoc), new StreamResult(out));
            ((SaajSoapMessage) message).getSaajMessage().getSOAPPart()
                    .setContent(new StreamSource(new ByteArrayInputStream(out.toByteArray())));

            logger.info("Business response prepared and set successfully.");
        } catch (Exception ex) {
            logger.error("Business rule validation failed", ex);
            throw new AccountValidationException("Validation failed", ex);
        }
    }

    /**
     * Extracts key fields like identifier, codeValue, transactionId, and systemId from the SOAP request.
     */
    private RequestParams extractParams(ValidateArrangementForPaymentRequest request) {
        String identifier = request.getArrangementIdentifier().getIdentifier();
        String codeValue = request.getArrangementIdentifier().getContext().getCodeValue();
        String txnId = request.getRequestHeader().getRequestIds().get(0).getTransactionId();
        String systemId = request.getRequestHeader().getRequestIds().get(0).getSystemId();
        logger.debug("Extracted request parameters: identifier={}, codeValue={}, txnId={}, systemId={}",
                identifier, codeValue, txnId, systemId);
        return new RequestParams(identifier, codeValue, identifier.length(), txnId, systemId);
    }

    /**
     * Validates error conditions such as invalid IBAN/UBAN format or mismatched values.
     */
    private Optional<ErrorDetail> determineError(RequestParams p) {
    ErrorDetail errorDetail = null;

    if (ServiceConstants.INTL_BANK_ACCOUNT.equals(p.codeValue())) {
        if (!p.identifier().startsWith("GB")) {
            errorDetail = ErrorConstants.ERR_WRONG_COUNTRY_CODE;
        } else if (p.length() != 22) {
            errorDetail = ErrorConstants.ERR_INVALID_IBAN_LENGTH;
        }
    } else if (ServiceConstants.UK_BASIC_BANK_ACCOUNT.equals(p.codeValue())) {
        if (p.identifier().startsWith("GB")) {
            errorDetail = ErrorConstants.ERR_DB2_SQL;
        } else if (p.length() != 14) {
            errorDetail = ErrorConstants.ERR_INVALID_UBAN_LENGTH;
        } else if (!isUbanValid(p.identifier())) {
            errorDetail = ErrorConstants.ERR_MOD97_UBAN;
        }
    }

    return Optional.ofNullable(errorDetail);
    }

    /**
     * Matches the request against known account types and configurations.
     */
    private Optional<ResponseConfig> determineMatchingConfig(RequestParams p) {

        Map<String, ResponseConfig> ruleMap = Map.of(
        IBAN_1, new ResponseConfig(DOMESTIC_RESTRICTED, SWITCHED, PASSED),
        IBAN_2, new ResponseConfig(DOMESTIC_RESTRICTED, NOT_SWITCHING, PASSED),
        IBAN_3, new ResponseConfig(DOMESTIC_UNRESTRICTED, SWITCHED, PASSED),
        IBAN_4, new ResponseConfig(DOMESTIC_UNRESTRICTED, NOT_SWITCHING, FAILED)
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
        return p.identifier.equals(account) || extractLast14Digits(account).equals(p.identifier);
    }

    /**
     * Verifies if the given UBAN matches the suffix of known IBANs.
     */
    private boolean isUbanValid(String identifier) {
        return ServiceConstants.ALL_IBANS.stream()
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
        logger.debug("Loading XML from path: {}", path);
        InputStream xml = getClass().getClassLoader().getResourceAsStream(path);
        if (xml == null) {
            logger.error("XML file not found at path: {}", path);
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
        updateText(xpath, doc, "//responseId/systemId", p.systemId);
        updateText(xpath, doc, "//responseId/transactionId", generateTxnId());
        updateText(xpath, doc, "//status", config.accountStatus.getValue());
        updateText(xpath, doc, "//switchingStatus", config.switchingStatus.getValue());
        updateText(xpath, doc, "//modulusCheckStatus/codeValue", config.modulusCheckStatus.getValue());
        logger.info("Updated response XML with success values");
    }

    /**
     * Populates values in the static error response XML.
     */
    private void applyErrorResponse(Document doc, XPath xpath, ErrorDetail errorDetail, String txnId) throws XPathExpressionException {
        updateText(xpath, doc, ErrorConstants.XPATH_RESPONSE_ID_TXN_ID, generateTxnId());
        updateText(xpath, doc, ErrorConstants.XPATH_REF_REQUEST_TXN_ID, txnId);
        updateText(xpath, doc, ErrorConstants.XPATH_CMD_STATUS, "Failed");
        updateText(xpath, doc, ErrorConstants.XPATH_CMD_DESCRIPTION, errorDetail.description);
        updateText(xpath, doc, ErrorConstants.XPATH_TIMESTAMP, ZonedDateTime.now().toString());
        updateText(xpath, doc, ErrorConstants.XPATH_RETURN_CODE, errorDetail.returnCode);
        if (errorDetail.systemNotificationDesc != null) {
            updateText(xpath, doc, ErrorConstants.XPATH_SYS_NOTIFICATION_DESC, errorDetail.systemNotificationDesc);
            updateText(xpath, doc, ErrorConstants.XPATH_SYS_NOTIFICATION_CODE, errorDetail.returnCode);
        } else {
            Node node = (Node) xpath.evaluate(ErrorConstants.XPATH_SYS_NOTIFICATION_BLOCK, doc, XPathConstants.NODE);
            if (node != null && node.getParentNode() != null) {
                node.getParentNode().removeChild(node);
                logger.debug("Removed systemNotification block as it was not applicable.");
            }
        }
        logger.info("Updated response XML with error values: {}", errorDetail.description);
    }

    /**
     * Utility method to update a specific XML node’s text content.
     */
    private void updateText(XPath xpath, Document doc, String path, String value) throws XPathExpressionException {
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null && value != null) {
            node.setTextContent(value);
            logger.debug("Updated XML node {} with value {}", path, value);
        }
    }

    /**
     * Generates a unique transaction ID string.
     */
    private String generateTxnId() {
        return "1alN" + UUID.randomUUID().toString().replace("-", "") + "h";
    }

    /**
     * Immutable container representing a valid request configuration.
     * this record is left without methods or additional logic,as it is only
     *  used to group and transport request fields such as
     *  <ul>
     *     <li>{@code identifier} - contains account number </li>
     *     <li>{@code codeValue} - used to identify
     * whether account is UKBasicBankAccountNumber or InternationalBankAccountNumber</li>
     *     <li>{@code length} - returns length of account number </li>
     *      <li>{@code originalTxnId} - return the transactionId of the request </li>
     *       <li>{@code systemId} - returns the systemId from the request </li>
     */
     @SuppressWarnings("unused")
    private record RequestParams(String identifier, String codeValue, int length, String originalTxnId,String systemId) {
    // this record is left without methods or additional logic,as it is only used to group and transport request fields
     }

    /**
     * Immutable container representing a valid account configuration.
     * this record is left without methods or additional logic,as it is only
     * used to group and transport validation results such as
     * <ul>
     *     <li>{@code accountStatus} - the classification of the account(eg , restricted,unrestricted)</li>
     *      <li>{@code switchingStatus} - whether the account has been switched or not switching </li>
     *       <li>{@code modulusStatus} - result of modulus check </li>
     * </ul>
     */
     @SuppressWarnings("unused")
    private record ResponseConfig(AccountStatus accountStatus, SwitchingStatus switchingStatus,ModulusCheckStatus modulusCheckStatus) {
     // this record is left without methods or additional logic,as it is only used to group and transport validation results
     }
}

--------------------
package com.rbs.bdd.application.service;

import com.rbs.bdd.application.port.out.AccountValidationPort;
import com.rbs.bdd.application.port.in.PaymentValidationPort;
import com.rbs.bdd.generated.ValidateArrangementForPaymentRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.ws.WebServiceMessage;

/**
 * Service class responsible for orchestrating the validation flow of payment arrangement requests.
 * Implements {@link PaymentValidationPort} and delegates schema and business rule validation
 * to the appropriate output port.
 */
@Service
@RequiredArgsConstructor
public class PaymentOrchestrator implements PaymentValidationPort {

    private final AccountValidationPort accountValidationPort;




    /**
     * Entry point for handling the SOAP request. Validates schema and applies business rules.
     *
     * @param request the incoming SOAP request payload
     * @param message the SOAP WebServiceMessage used to write the final response
     */
    @Override
    public void validateArrangementForPayment(ValidateArrangementForPaymentRequest request,WebServiceMessage message) {
        accountValidationPort.validateSchema(request); // automatic validation through interceptors
         accountValidationPort.validateBusinessRules(request,message);
    }

}


-------------

package com.rbs.bdd.common;

import com.rbs.bdd.domain.enums.model.ErrorDetail;

/**
 * Centralized constants used for generating error responses in {@link com.rbs.bdd.application.service.AccountValidationService}.
 * <p>
 * This includes:
 * <ul>
 *     <li>XPath expressions used to locate and update XML response elements</li>
 *     <li>Predefined {@link ErrorDetail} instances used to represent different validation errors</li>
 * </ul>
 * These constants help ensure consistency across all error response transformations.
 */
public final class ErrorConstants {

    /**
     * Private constructor to prevent instantiation.
     */
    private ErrorConstants() {}

    // ─────────────────────────────────────────────────────
    // XPath Expressions for XML Node Updates
    // ─────────────────────────────────────────────────────

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
    public static final String XPATH_SYS_NOTIFICATION_DESC = "//*[local-name()='systemNotifications']/*[local-name()='description']";

    /**
     * XPath to locate returnCode inside systemNotifications block.
     */
    public static final String XPATH_SYS_NOTIFICATION_CODE = "//*[local-name()='systemNotifications']/*[local-name()='returnCode']";

    /**
     * XPath to locate the entire systemNotifications block node.
     */
    public static final String XPATH_SYS_NOTIFICATION_BLOCK = "//*[local-name()='systemNotifications']";

    // ─────────────────────────────────────────────────────
    // Predefined Error Responses
    // ─────────────────────────────────────────────────────

    /**
     * Error returned when the IBAN length is not 22 characters.
     */
    public static final ErrorDetail ERR_INVALID_IBAN_LENGTH = new ErrorDetail(
            "ERR006",
            "Length of IBAN is Invalid",
            "0013",
            "Length of IBAN is Invalid"
    );

    /**
     * Error representing a failure in DB2 SQL lookup for the sort code or account.
     */
    public static final ErrorDetail ERR_DB2_SQL = new ErrorDetail(
            "ERR006",
            "500|Service GRPUB.OA_GET_SORTCODE_DETAILS...(OA2.2105271236)...",
            null,
            null
    );

    /**
     * Error returned when the IBAN does not start with a valid GB country code.
     */
    public static final ErrorDetail ERR_WRONG_COUNTRY_CODE = new ErrorDetail(
            "0010",
            "Country code is not found in Db, try  with the correct country code",
            null,
            null
    );

    /*
     * Common error code used to representgeneral service or validation failure
     */
    public static final String ERROR_CODE_ERR06="ERROO6";

    /**
     * Error returned when MOD97 validation fails for the IBAN.
     */
    public static final ErrorDetail ERR_MOD97_IBAN = new ErrorDetail(
            ERROR_CODE_ERR06,
            "MOD97 failure for the IBAN",
            "0020",
            "MOD97 failure for the IBAN"
    );

    /**
     * Error returned when the UBAN length is not exactly 14 characters.
     */
    public static final ErrorDetail ERR_INVALID_UBAN_LENGTH = new ErrorDetail(
            ERROR_CODE_ERR06,
            "UBAN should be 14 digits",
            "0013",
            "UBAN should be 14 digits"
    );

    /**
     * Error returned when MOD97 validation fails for the UBAN.
     */
    public static final ErrorDetail ERR_MOD97_UBAN = new ErrorDetail(
            ERROR_CODE_ERR06,
            "MOD97 failure for the UBAN",
            "0020",
            "MOD97 failure for the UBAN"
    );
}

--------------
package com.rbs.bdd.common;

import java.util.List;

/**
 * Centralized constants used across the application for:
 *
 *   IBAN and code value mappings
 *   File paths for static SOAP responses
 *   XPath expressions for XML manipulation
 *
 * These constants help standardize values and avoid repetition throughout the service layer,
 * particularly within the SOAP response handling and validation logic.
 */
public final class ServiceConstants {

    /**
     * Path to the default error SOAP response XML used when validation fails.
     */
    public static final String ERROR_XML_PATH = "error-response/error-response.xml";

    /**
     * Path to the schema validation-specific SOAP error response.
     */
    public static final String SCHEMA_VALIDATION_ERROR_XML = "error-response/SchemaValidationError.xml";

    // ─────────────────────────────────────────────────────
    // IBAN Constants for Matching Configurations
    // ─────────────────────────────────────────────────────

    /**
     * Configured IBAN representing a Domestic-Restricted, Switched, Modulus Passed account.
     */
    public static final String IBAN_1 = "GB29NWBK60161331926801";

    /**
     * Configured IBAN representing a Domestic-Restricted, Not Switching, Modulus Passed account.
     */
    public static final String IBAN_2 = "GB82WEST12345698765437";

    /**
     * Configured IBAN representing a Domestic-Unrestricted, Switched, Modulus Passed account.
     */
    public static final String IBAN_3 = "GB94BARC10201530093422";

    /**
     * Configured IBAN representing a Domestic-Unrestricted, Not Switching, Modulus Failed account.
     */
    public static final String IBAN_4 = "GB33BUKB20201555555567";

    /**
     * List of all supported IBANs used for validation and suffix matching.
     */
    public static final List<String> ALL_IBANS = List.of(
            IBAN_1,
            IBAN_2,
            IBAN_3,
            IBAN_4
    );

    // ─────────────────────────────────────────────────────
    // Code Values for Identifying Account Type
    // ─────────────────────────────────────────────────────

    /**
     * Code value representing an international bank account (IBAN).
     */
    public static final String INTL_BANK_ACCOUNT = "InternationalBankAccountNumber";

    /**
     * Code value representing a UK basic bank account (UBAN).
     */
    public static final String UK_BASIC_BANK_ACCOUNT = "UKBasicBankAccountNumber";

    // ─────────────────────────────────────────────────────
    // Static Response XML Paths
    // ─────────────────────────────────────────────────────

    /**
     * Path to the static success SOAP response XML used when business rules pass.
     */
    public static final String RESPONSE_XML_PATH = "static-response/response1.xml";

    // ─────────────────────────────────────────────────────
    // XPath Expressions for XML Node Access/Manipulation
    // ─────────────────────────────────────────────────────

    /**
     * XPath to locate any transactionId in the response.
     */
    public static final String XPATH_TRANSACTION_ID = "//*[local-name()='transactionId']";

    /**
     * XPath to locate account status under accountingUnits.
     */
    public static final String XPATH_ACCOUNT_STATUS = "//*[local-name()='accountingUnits']/*[local-name()='status']/*[local-name()='codeValue']";

    /**
     * XPath to locate switching status value.
     */
    public static final String XPATH_SWITCHING_STATUS = "//*[local-name()='switchingStatus']/*[local-name()='codeValue']";

    /**
     * XPath to locate modulus check status code value.
     */
    public static final String XPATH_MODULUS_STATUS = "//*[local-name()='modulusCheckStatus']/*[local-name()='codeValue']";

    // ─────────────────────────────────────────────────────
    // XPath Expressions for Fault/Error Response Nodes
    // ─────────────────────────────────────────────────────

    /**
     * XPath to locate transactionId inside refRequestIds in a SOAP Fault response.
     */
    public static final String XPATH_FAULT_TRANSACTION_ID = "//*[local-name()='refRequestIds']/*[local-name()='transactionId']";

    /**
     * XPath to locate the full responseId block in a SOAP Fault.
     */
    public static final String XPATH_FAULT_RESPONSE_ID = "//*[local-name()='responseId']";

    /**
     * XPath to locate the timestamp node in a SOAP Fault.
     */
    public static final String XPATH_FAULT_TIMESTAMP = "//*[local-name()='timestamp']";


    /**
     * XML Tage name used to identify the transactionId element in the request
     */
    public static final String TAG_TRANSACTION_ID= "transactionId";

    /**
     * Private constructor to prevent instantiation.
     */
    private ServiceConstants() {
        // Prevent instantiation
    }
}

------------------
package com.rbs.bdd.domain.enums.model;



/**
 * Model representing error details used in SOAP error responses.
 * Includes return code, user-facing description, and system notification code/description.
 */
public class ErrorDetail {
    public final String returnCode;
    public final String description;
    public final String systemNotificationCode;
    public final String systemNotificationDesc;

    public ErrorDetail(String returnCode, String description, String systemNotificationCode, String systemNotificationDesc) {
        this.returnCode = returnCode;
        this.description = description;
        this.systemNotificationCode = systemNotificationCode;
        this.systemNotificationDesc = systemNotificationDesc;
    }
}

-----------------------
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


--------------------
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

----
package com.rbs.bdd.infrastructure.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.EndpointInterceptor;

import java.io.ByteArrayOutputStream;
/**
 * Interceptor to log incoming and outgoing SOAP messages for debugging and monitoring.
 * This class logs the full request, response, and fault messages.
 */
public class SoapLoggingInterceptor implements EndpointInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(SoapLoggingInterceptor.class);

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
            logger.info("{}:\n{}", type, out.toString());  // Log the message content
        } catch (Exception e) {
            logger.error("Error logging {} message: {}", type, e.getMessage());
        }
    }
}

-----
package com.rbs.bdd.infrastructure.config;

import com.rbs.bdd.application.exception.SchemaValidationException;
import com.rbs.bdd.application.exception.XsdSchemaLoadingException;
import com.rbs.bdd.infrastructure.soap.interceptor.SchemaValidationInterceptor;
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
        SchemaValidationInterceptor validatingInterceptor = new SchemaValidationInterceptor();
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
    public DefaultWsdl11Definition defaultWsdl11Definition() throws SchemaValidationException {
        DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
        wsdl11Definition.setPortTypeName("IArrValidationForPayment");
        wsdl11Definition.setLocationUri("/ws");
        wsdl11Definition.setTargetNamespace("http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/");
        wsdl11Definition.setSchemaCollection(updateContactXsd());
        return wsdl11Definition;
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
        try {
            CommonsXsdSchemaCollection xsd = new CommonsXsdSchemaCollection(
                    new ClassPathResource("xsd/ArrValidationForPaymentParameters.xsd"));
            xsd.setInline(true);
            return xsd;
        } catch (Exception e) {
            throw new XsdSchemaLoadingException("Failed to load XSD schema for SOAP validation", e);
        }
    }
}

--------------
package com.rbs.bdd.infrastructure.soap.api;

import com.rbs.bdd.application.port.in.PaymentValidationPort;
import com.rbs.bdd.generated.ValidateArrangementForPaymentRequest;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;


/**
 * SOAP endpoint adapter class for handling the `validateArrangementForPayment` operation.
 * It uses Spring WS annotations to route incoming SOAP requests to the appropriate service layer.
 */
@Endpoint
public class PaymentValidationSoapAdapter {

    /**Changes for the request*/

    private static final String NAMESPACE_URI = "http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/";
    private final PaymentValidationPort paymentValidationPort;

    /**
     * Constructor-based injection of the orchestrator that handles business logic.
     *
     * @param paymentValidationPort the orchestrator service
     */
    public PaymentValidationSoapAdapter(PaymentValidationPort paymentValidationPort) {
        this.paymentValidationPort = paymentValidationPort;
    }

    /**
     * Handles the `validateArrangementForPayment` SOAP request.
     * Delegates request processing to the orchestrator which modifies the response message directly.
     *
     * @param request the SOAP request payload
     * @param context the Spring WS message context
     */
    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "validateArrangementForPayment")
    @ResponsePayload
    public void validateArrangementForPayment(@RequestPayload ValidateArrangementForPaymentRequest request,
                                                MessageContext context) {

        WebServiceMessage response = context.getResponse();
        paymentValidationPort.validateArrangementForPayment(request, response);
         }

}



--------------
package com.rbs.bdd.infrastructure.soap.interceptor;


import com.rbs.bdd.application.exception.SchemaValidationException;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.ws.WebServiceMessage;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.server.endpoint.interceptor.PayloadValidatingInterceptor; import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
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

import static com.rbs.bdd.common.ServiceConstants.SCHEMA_VALIDATION_ERROR_XML;
import static com.rbs.bdd.common.ServiceConstants.TAG_TRANSACTION_ID;


/**
 * Intercepts schema validation errors in SOAP requests and returns a custom SOAP fault response.
 * The response is based on a static XML file, with dynamic fields replaced using request data.
 */
public class SchemaValidationInterceptor extends PayloadValidatingInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(SchemaValidationInterceptor.class);

    private static final String PLACEHOLDER_TXN = "TXN_ID_PLACEHOLDER";
    private static final String PLACEHOLDER_RESPONSE = "RESPONSE_ID_PLACEHOLDER";

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
        logger.warn("Schema validation failed. Returning custom schemaValidationError.xml");

        try (InputStream staticXml = getClass().getClassLoader().getResourceAsStream(SCHEMA_VALIDATION_ERROR_XML)) {
            if (staticXml == null) {
                logger.error("schemaValidationError.xml not found");
                return true;
            }

            DocumentBuilder builder = getSecureDocumentBuilder();
            Document errorDoc = builder.parse(staticXml);
            Document requestDoc = extractRequestDocument(messageContext, builder);

            updateDynamicFields(errorDoc, requestDoc);

            sendCustomSoapFault(errorDoc);
            return false;
        } catch (Exception e) {
            logger.error("Error during schema validation interception", e);
            throw new SchemaValidationException("Schema validation failure", e);
        }
    }

    /**
     * Creates a secure, namespace-aware {@link DocumentBuilderFactory}.
     * <p>
     * This method disables external entity processing to prevent XML External Entity (XXE)
     * attacks and other injection vulnerabilities.
     *
     *
     * @return configured {@link DocumentBuilderFactory} instance
     * @throws ParserConfigurationException if security features cannot be set
     */
    private DocumentBuilder getSecureDocumentBuilder() throws ParserConfigurationException {
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



    /**
     * Parses the incoming request message into a Document.
     */
    private Document extractRequestDocument(MessageContext messageContext, DocumentBuilder builder) throws IOException, SAXException {
        WebServiceMessage request = messageContext.getRequest();
        ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
        request.writeTo(requestBytes);
        return builder.parse(new ByteArrayInputStream(requestBytes.toByteArray()));
    }

    /**
     * Updates transaction ID, timestamp, and cleans up the response XML dynamically.
     */
    private void updateDynamicFields(Document errorDoc, Document requestDoc) throws XPathExpressionException {
        String txnId = getValueFromRequest(requestDoc, TAG_TRANSACTION_ID);
        String systemId = getValueFromRequest(requestDoc, "systemId");

        replaceTextNode(errorDoc, PLACEHOLDER_RESPONSE, generateTxnId());
        replaceTextNode(errorDoc, PLACEHOLDER_TXN, txnId != null ? txnId : PLACEHOLDER_TXN);
        setXPathValue(errorDoc, "//*[local-name()='timestamp']",
                OffsetDateTime.now(ZoneId.of("Europe/London")).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));

        handleRefRequestIds(errorDoc, requestDoc, txnId, systemId);
    }

    /**
     * Handles removal of <refRequestIds> node if <requestIds> is missing or empty.
     */
    private void handleRefRequestIds(Document errorDoc, Document requestDoc, String txnId, String systemId) {
        Node requestIds = getNode(requestDoc, "requestIds");
        boolean isEmpty = isNodeEmpty(requestIds);

        Node refRequestIds = getNode(errorDoc, "refRequestIds");

        if (isEmpty  && refRequestIds != null) {
            refRequestIds.getParentNode().removeChild(refRequestIds);
            return;
        }

        if (refRequestIds != null) {
            if (txnId == null) removeNode(refRequestIds, "transactionId");
            if (systemId == null) removeNode(refRequestIds, "systemId");
            if (!refRequestIds.hasChildNodes()) {
                refRequestIds.getParentNode().removeChild(refRequestIds);
            }
        }
    }

    /**
     * Sends the final SOAP error response with HTTP 500.
     */
    private void sendCustomSoapFault(Document errorDoc) throws TransformerException, IOException {
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
            servletResponse.flushBuffer();
        }
    }

    /**
     * Retrieves the text content of a given tag from the request document.
     */
    private String getValueFromRequest(Document doc, String tag) {
        NodeList list = doc.getElementsByTagNameNS("*", tag);
        return list.getLength() > 0 ? list.item(0).getTextContent() : null;
    }

    /**
     * Finds a node by its local name using wildcard namespace.
     */
    private Node getNode(Document doc, String localName) {
        NodeList nodes = doc.getElementsByTagNameNS("*", localName);
        return nodes.getLength() > 0 ? nodes.item(0) : null;
    }

    /**
     * Replaces a text node matching a placeholder with a new value.
     */
    private void replaceTextNode(Document doc, String placeholder, String newValue) {
        NodeList nodes = doc.getElementsByTagNameNS("*", "transactionId");
        for (int i = 0; i < nodes.getLength(); i++) {
            Node txn = nodes.item(i);
            if (placeholder.equals(txn.getTextContent())) {
                txn.setTextContent(newValue);
            }
        }
    }

    /**
     * Sets a value for the node matching the given XPath expression.
     */
    private void setXPathValue(Document doc, String path, String value) throws XPathExpressionException {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null) {
            node.setTextContent(value);
        }
    }

    /**
     * Removes a specific child element from the parent node.
     */
    private void removeNode(Node parent, String tagName) {
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
     * Checks if the given node is empty or only contains non-element children.
     */
    private boolean isNodeEmpty(Node node) {
        if (node == null) return true;
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == Node.ELEMENT_NODE) return false;
        }
        return true;
    }

    /**
     * Generates a unique transaction ID using UUID.
     */
    private String generateTxnId() {
        return "1alN" + UUID.randomUUID().toString().replace("-", "") + "h";
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

--------------
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
@SpringBootApplication(scanBasePackages = "com.rbs.bdd")
public class EspSimulatorEngine {

    public static void main(String[] args) {
        SpringApplication.run(EspSimulatorEngine.class, args);
    }
}

-----

SchemaValidationError.xml

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


---------------

error-response.xml 
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ns="http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/">
    <soapenv:Header/>
    <soapenv:Body>
        <ns:validateArrangementForPaymentResponse>
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
                    <description>Error description placeholder</description>
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
        </ns:validateArrangementForPaymentResponse>
    </soapenv:Body>
</soapenv:Envelope>

-----------
response1.xml

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


-------------------------

Now i want the code for Customer Retrieval Endpoint also and integrate in the existing code 

1. Request 
<crfpSP:retrievePrimaryCustomerForArrRequest xmlns:crfpSP="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/ CustomerRetrievalForPaymentParameters.xsd ">
<requestHeader>
<operatingBrand>NWB</operatingBrand>
<requestIds>
<systemId>RequestID</systemId>
<transactionId>FPMB6107012345678</transactionId>
</requestIds>
<requestIds>
<systemId>SourceID</systemId>
<transactionId>XCT</transactionId>
</requestIds>
</requestHeader>
<arrangementIdentifier>
<identifier>08000012345678</identifier>
<context>
<schemeName>ArrangementEnterpriseIdType</schemeName>
<codeValue>UKBasicBankAccountNumber</codeValue>
</context>
</arrangementIdentifier>
</crfpSP:retrievePrimaryCustomerForArrRequest>

2. Response 
This XML file does not appear to have any style information associated with it. The document tree is shown below.
<crfpSP:retrievePrimaryCustomerForArrResponse xmlns:crfpSP="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/ CustomerRetrievalForPaymentParameters.xsd ">
<response>
<responseHeader/>
<customer xsi:type="crfpTO:Organization_TO">
<universalUniqueIdentifier>
<identifier>1122334455</identifier>
<context>
<schemeName>CustomerEnterpriseIdType</schemeName>
<codeValue>BusinessIdentificationNumber</codeValue>
</context>
</universalUniqueIdentifier>
<isClassifiedBy xsi:type="crfpTO:ClassificationValue_TO">
<codeValue>B</codeValue>
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
<address>Addressee name 1</address>
<!-- Note: This will not be present for an International Account Customer -->
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine2</codeValue>
<address>Addressee name 2</address>
<!-- Note: This will not be present for an International Account Customer -->
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine1</codeValue>
<address>1 North Street</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine2</codeValue>
<address>North Town</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine3</codeValue>
<address>North City</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine4</codeValue>
<address>Northshire</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine5</codeValue>
<address/>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>PostalCode</codeValue>
<address>AB123CB</address>
</hasComponent>
<postalCodeExemptionReason>
<schemeName>PostalCodeExemptionReasonType</schemeName>
<codeValue>codevalue</codeValue>
</postalCodeExemptionReason>
<!-- For a domestic account - this element is only present if the /customer/hasForContactPreference/correspondenceDestinationPreference element is NOT present, i.e. Return to Branch has not been specified as a correspondence destination preference.  -->
<!-- This element will always be present for an International account. -->
</contactPoint>
<correspondenceDestinationPreference>
<schemeName>CorrespondenceDestinationPreferenceType</schemeName>
<codeValue> </codeValue>
<!-- Note: This will not be present for an International Account Customer -->
<!-- For a domestic account - this element is only present if the /customer/hasForContactPreference/contactPoint element is NOT present.
   -->
<!--  A value of R indicates the Return To Branch correspondence preference in which case there will be no address details. -->
</correspondenceDestinationPreference>
</hasForContactPreference>
<hasForName xsi:type="crfpTO:InvolvedPartyName_TO">
<nameText>The Company</nameText>
<usage>
<schemeName>InvolvedPartyNameType</schemeName>
<codeValue>CompanyName</codeValue>
</usage>
</hasForName>
<isSensitive>true</isSensitive>
<hasLegalAddress>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine1</codeValue>
<address>1 North Street</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine2</codeValue>
<address>North Town</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine3</codeValue>
<address>North City</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine4</codeValue>
<address>Northshire</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine5</codeValue>
<address/>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>PostalCode</codeValue>
<address>AB123CB</address>
</hasComponent>
<postalCodeExemptionReason>
<schemeName>PostalCodeExemptionReasonType</schemeName>
<codeValue>codevalue</codeValue>
</postalCodeExemptionReason>
</hasLegalAddress>
<hasPartyType>
<schemeName>InvolvedPartyType</schemeName>
<codeValue>Organisation</codeValue>
</hasPartyType>
<hasInvolvedPartyAssociation>
<associatedInvolvedParty xsi:type="crfpTO:Individual_TO">
<hasForName xsi:type="crfpTO:IndividualName_TO">
<middleNames>middleNames</middleNames>
<prefixTitle>
<schemeName>IndividualNamePrefixType</schemeName>
<codeValue>Mr</codeValue>
</prefixTitle>
<firstName>firstName</firstName>
<lastName>lastName</lastName>
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
</crfpSP:retrievePrimaryCustomerForArrResponse>

-----------------------
1. request.xml 

<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" version="RBS_20210325_Baseline" xmlns:crfpSP="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/">
  <xsd:import namespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" schemaLocation="CustomerRetrievalForPaymentTransferObjects.xsd"/>
  <xsd:import namespace="http://com/rbsg/soa/Services/Definitions/V03/" schemaLocation="ServiceDefinitions.xsd"/>
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="retrievePrimaryCustomerForArrRequest">
    <xsd:sequence>
      <xsd:element name="requestHeader" type="sdef:RequestHeader"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="processingParameter" type="pdt:Property"/>
      <xsd:element name="arrangementIdentifier" type="pdt:ObjectReference">
        <xsd:annotation>
          <xsd:documentation>Identifier of the account for which the Customer is identified as the Primary Customer (Account Owner).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="RetrievePrimaryCustomerForArrContent">
    <xsd:sequence>
      <xsd:element name="responseHeader" type="sdef:ResponseHeader"/>
      <xsd:element minOccurs="0" name="customer" type="crfpTO:InvolvedParty_TO"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="modifyToken" type="pdt:Property"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="retrievePrimaryCustomerForArrResponse">
    <xsd:sequence>
      <xsd:choice>
        <xsd:element name="response" type="crfpSP:RetrievePrimaryCustomerForArrContent"/>
        <xsd:element name="exception" type="sdef:Exception"/>
      </xsd:choice>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>

-----------------

response.xml

This XML file does not appear to have any style information associated with it. The document tree is shown below.
<crfpSP:retrievePrimaryCustomerForArrResponse xmlns:crfpSP="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/ CustomerRetrievalForPaymentParameters.xsd ">
<response>
<responseHeader/>
<customer xsi:type="crfpTO:Organization_TO">
<universalUniqueIdentifier>
<identifier>1122334455</identifier>
<context>
<schemeName>CustomerEnterpriseIdType</schemeName>
<codeValue>BusinessIdentificationNumber</codeValue>
</context>
</universalUniqueIdentifier>
<isClassifiedBy xsi:type="crfpTO:ClassificationValue_TO">
<codeValue>B</codeValue>
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
<address>Addressee name 1</address>
<!-- Note: This will not be present for an International Account Customer -->
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine2</codeValue>
<address>Addressee name 2</address>
<!-- Note: This will not be present for an International Account Customer -->
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine1</codeValue>
<address>1 North Street</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine2</codeValue>
<address>North Town</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine3</codeValue>
<address>North City</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine4</codeValue>
<address>Northshire</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine5</codeValue>
<address/>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>PostalCode</codeValue>
<address>AB123CB</address>
</hasComponent>
<postalCodeExemptionReason>
<schemeName>PostalCodeExemptionReasonType</schemeName>
<codeValue>codevalue</codeValue>
</postalCodeExemptionReason>
<!-- For a domestic account - this element is only present if the /customer/hasForContactPreference/correspondenceDestinationPreference element is NOT present, i.e. Return to Branch has not been specified as a correspondence destination preference.  -->
<!-- This element will always be present for an International account. -->
</contactPoint>
<correspondenceDestinationPreference>
<schemeName>CorrespondenceDestinationPreferenceType</schemeName>
<codeValue> </codeValue>
<!-- Note: This will not be present for an International Account Customer -->
<!-- For a domestic account - this element is only present if the /customer/hasForContactPreference/contactPoint element is NOT present.
   -->
<!--  A value of R indicates the Return To Branch correspondence preference in which case there will be no address details. -->
</correspondenceDestinationPreference>
</hasForContactPreference>
<hasForName xsi:type="crfpTO:InvolvedPartyName_TO">
<nameText>The Company</nameText>
<usage>
<schemeName>InvolvedPartyNameType</schemeName>
<codeValue>CompanyName</codeValue>
</usage>
</hasForName>
<isSensitive>true</isSensitive>
<hasLegalAddress>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine1</codeValue>
<address>1 North Street</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine2</codeValue>
<address>North Town</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine3</codeValue>
<address>North City</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine4</codeValue>
<address>Northshire</address>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>AddressLine5</codeValue>
<address/>
</hasComponent>
<hasComponent>
<schemeName>PostalAddressComponentType</schemeName>
<codeValue>PostalCode</codeValue>
<address>AB123CB</address>
</hasComponent>
<postalCodeExemptionReason>
<schemeName>PostalCodeExemptionReasonType</schemeName>
<codeValue>codevalue</codeValue>
</postalCodeExemptionReason>
</hasLegalAddress>
<hasPartyType>
<schemeName>InvolvedPartyType</schemeName>
<codeValue>Organisation</codeValue>
</hasPartyType>
<hasInvolvedPartyAssociation>
<associatedInvolvedParty xsi:type="crfpTO:Individual_TO">
<hasForName xsi:type="crfpTO:IndividualName_TO">
<middleNames>middleNames</middleNames>
<prefixTitle>
<schemeName>IndividualNamePrefixType</schemeName>
<codeValue>Mr</codeValue>
</prefixTitle>
<firstName>firstName</firstName>
<lastName>lastName</lastName>
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
</crfpSP:retrievePrimaryCustomerForArrResponse>



-----------------


CustomerRetrievalForPaymentParameters.xsd


<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" version="RBS_20210325_Baseline" xmlns:crfpSP="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/">
  <xsd:import namespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" schemaLocation="CustomerRetrievalForPaymentTransferObjects.xsd"/>
  <xsd:import namespace="http://com/rbsg/soa/Services/Definitions/V03/" schemaLocation="ServiceDefinitions.xsd"/>
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="retrievePrimaryCustomerForArrRequest">
    <xsd:sequence>
      <xsd:element name="requestHeader" type="sdef:RequestHeader"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="processingParameter" type="pdt:Property"/>
      <xsd:element name="arrangementIdentifier" type="pdt:ObjectReference">
        <xsd:annotation>
          <xsd:documentation>Identifier of the account for which the Customer is identified as the Primary Customer (Account Owner).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="RetrievePrimaryCustomerForArrContent">
    <xsd:sequence>
      <xsd:element name="responseHeader" type="sdef:ResponseHeader"/>
      <xsd:element minOccurs="0" name="customer" type="crfpTO:InvolvedParty_TO"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="modifyToken" type="pdt:Property"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="retrievePrimaryCustomerForArrResponse">
    <xsd:sequence>
      <xsd:choice>
        <xsd:element name="response" type="crfpSP:RetrievePrimaryCustomerForArrContent"/>
        <xsd:element name="exception" type="sdef:Exception"/>
      </xsd:choice>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>

-------------------------

CustomerRetrievalForPaymentTransferObjects.xsd

<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" version="RBS_20210325_Baseline" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/">
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="BaseTransferObject">
    <xsd:sequence>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="extendedProperties" type="pdt:Property"/>
      <xsd:element minOccurs="0" name="lastUpdateToken" type="pdt:PropertyVariant">
        <xsd:annotation>
          <xsd:documentation>Datetime for objects that require optimistic locking on update.  The datetime retrieved is passed back on the update operation and validated against the last updated datetime stored for the object.  If they are the same, the update can go ahead.  If not, another update has occurred in the interim and the update is rejected.

As this is on the BaseTransferObject, it can be used selectively for those objects within a retrieve and update operation response / request parameter set, that require such optimistic locking.  This a a set on BMOs and the constituent dependent types, can be used to form a set of lock tokens.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ContactPoint_TO">
    <xsd:annotation>
      <xsd:documentation>The method and destination of a communication contact with a Role Player. This relates to specific communication media: Postal Address, Telephone Number, Electronic Address, Care Of Address </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="priorityLevel" type="pdt:Number">
            <xsd:annotation>
              <xsd:documentation>The relative priority level of one Contact Point over another.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="usage" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The context in which a Role Player uses this Contact Point. eg Primary Residence, Work etc</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasComponent" type="pdt:AddressComponent">
            <xsd:annotation>
              <xsd:documentation>Individual components of a postal address e.g. City, PostCode etc</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="lifecycleStatus" type="pdt:LifecycleStatus">
            <xsd:annotation>
              <xsd:documentation>Lifecycle status of the Contact Point e.g Active, Inactive etc </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="contactPointType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Identifies the type of Contact Point under consideration eg Postal Address, Telephone number etc </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="PostalAddress_TO">
    <xsd:annotation>
      <xsd:documentation>An address used for the delivery of letters and packages by an external mailing or package service, at a place where the recipient usually lives or works. The structure of a postal address depends on the country of the postal address, for this reason a Postal Address is made up of a number of Postal Address Components. </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:ContactPoint_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="postalCodeExemptionReason" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The exempt type of the Postal Address, which indicates whether the postal address is exempted in having a Postal Code.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="GeographicArea_TO">
    <xsd:complexContent>
      <xsd:extension base="crfpTO:ClassificationValue_TO"/>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="ClassificationValue_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a grouping of Business Model Objects, for example; Single Males Under 30, Married People over 50, etc... A Classification Value can be further partitioned into several sub-classifications according to different criteria, each of which is represented in turn by a Classification Scheme.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="schemeName" type="pdt:String"/>
          <xsd:element minOccurs="0" name="codeValue" type="pdt:String"/>
          <xsd:element minOccurs="0" name="name" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The word or phrase that identifies (but not uniquely) the classification value.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="shortName" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>An abridged version of classificationValue name Example: For retrieving job title reference data, If the name of the value is AGRICULTURAL WORKER, the shortName is AG</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="ConditionContext_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies the &lt;Business&gt; to which a &lt;Condition&gt; relates</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="priority" type="pdt:String"/>
          <xsd:element minOccurs="0" name="occurrenceNumber" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>A reference number which signifies the occurrence of the Condition applying to the product Arrangement </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="startDate" type="pdt:DateTime">
            <xsd:annotation>
              <xsd:documentation>The date on which this Condition becomes appicable to the ProductArrangement.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="endDate" type="pdt:Date">
            <xsd:annotation>
              <xsd:documentation>The date from when this Condition is no longer applicable to the ProductArrangement. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Condition_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies the specific requirements that pertain to how the business of the modeled organization is conducted and includes information such as prerequisite or qualification criteria and restrictions or limits associated with the requirements. Conditions can apply to various aspects of a Financial Institution's operations, such as the sale and servicing of Products or the determination of eligibility to purchase a product.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="name" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The word or phrase used to identify (but not uniquely) the Condition.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="conditionValue" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>Identifies a Condition Descriptor that defines the measurable content that applies to a Condition. A Condition Value can be numeric, textual or an indicator (Yes, No). Numeric Condition Values can be qualified by a Unit Of Measure.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="code" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>This can be used for any Condition codes.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="hasConditionContext" type="crfpTO:ConditionContext_TO"/>
          <xsd:element minOccurs="0" name="purposeType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Distinguishes between Conditions according to the business activity they support or assist in accomplishing. Values within this Scheme are not mutually exclusive. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType abstract="true" name="BusinessModelObject_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies the highest class of objects in the hierarchy of the Financial Services Business Object Model representing a thing or a concept that is meaningful to the modeled Organization. Business Model Objects are superclasses of many objects that have business significance to business people and are used to provide common behavior across many object definitions. Examples of Business Model Object subclasses are Accounting Unit, Arrangement, Channel, Event, Product etc.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="universalUniqueIdentifier" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>Unique identifier for the Business Model Object</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="alternativeIdentifier" type="pdt:ObjectReference"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="isClassifiedBy" type="crfpTO:ClassificationValue_TO"/>
          <xsd:element minOccurs="0" name="objectType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The dynamic type for an instance of an object. E.g. for a DepositArrangement, this might specify FixedTermDepositArrangement to qualify what attributes are meaningful.Used to dynamically type an object as an instance of the specified type.Where an object has been created as a Testing/Training or Production object (e.g operationalNature), then the objectType Reference will be replaced by ObjectType, which includes an additional operationalNature element to reflect this where meaningful (e.g. "DepositArrangementType", "FixedTermDeposit", "Training"). The default value if a Reference is used rather than ObjectType, should be "Production"</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasConditions" type="crfpTO:Condition_TO">
            <xsd:annotation>
              <xsd:documentation>Identifies the Conditions to which the Business Model Objects refers</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="description" type="pdt:String"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Registration_TO">
    <xsd:annotation>
      <xsd:documentation>A formal granting, by an authorized body, of rights, privileges, favors, statuses, or qualifications. Registrations are important from the perspective of being a qualified source of information. Note that a Registration represents the actual granting, not the Document that represents those rights. that document is a Registration Document.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="isIssuedIn" type="crfpTO:GeographicArea_TO"/>
          <xsd:element minOccurs="0" name="lifeCycleStatus" type="pdt:LifecycleStatus">
            <xsd:annotation>
              <xsd:documentation>Life cycle status of the Registration</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="placeOfIssue" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>Place of the registration</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Customer_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party Role played by an Involved Party that is considered to be receiving services or products from the modeled organization or one of its Organization Units, or who is a potential recipient of such services or products.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedPartyRole_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="kycAssessmentChannel" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Specifies which channel carried out the Know Your Customer (KYC) assessment for the given customer. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedPartyRole_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular role played by a Role Player in a specific context. This role can specify additional information specific to the context, such as a mailing address for an account holder. The role can be identified independently of the context if the details are unavailable or irrelevant.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:RolePlayer_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="hasForContext" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>The identification of a Business Model Object as the context of an Involved Party Role</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="roleType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="lifecycleStatus" type="pdt:LifecycleStatus"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="ContactPreference_TO">
    <xsd:annotation>
      <xsd:documentation>The characteristics related to the way a Role Player wants to be contacted. This includes the contact points, the language, medium, name and timing preferences, the preferred contacting Individual as well as restrictions on the contact frequency. It also defines the usage such as business or private and the purpose, such as billing or mailing. </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="contactPoint" type="crfpTO:ContactPoint_TO">
            <xsd:annotation>
              <xsd:documentation>One or more points of contact for the Role Player under this Contact Preference</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="coveredArrangements" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>Returns the Arrangements that are covered by this Contact Preference </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="correspondenceDestinationPreference" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>In relation to Arrangements held by the RolePlayer, the destination preference for correspondence on that Arrangement. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType abstract="true" name="RolePlayer_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies an Involved Party or a role played by an Involved Party within the context of the modeled organization.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="firstContactDate" type="pdt:String"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="isPlayingRole" type="crfpTO:InvolvedPartyRole_TO"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="isRegisteredIn" type="crfpTO:PartyRegistration_TO"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasForContactPreference" type="crfpTO:ContactPreference_TO"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="PartyRegistration_TO">
    <xsd:annotation>
      <xsd:documentation>An official recognition related to a Role Player. A Party Registration may be backed up by a Documentation Item</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:Registration_TO">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="registersParty" type="crfpTO:RolePlayer_TO">
            <xsd:annotation>
              <xsd:documentation>Identifies the Involved Partys that are the subjects of a Party Registration.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="NationalRegistration_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Party Registration that certifies an Involved Party as belonging to or governed by a national governmental entity. For example, social security registration, taxpayer identification, passport, citizenship identity card are forms of National Registration.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:PartyRegistration_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="countryCode" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="hasPrimaryResidence" type="pdt:Boolean"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="IndividualName_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a name structure used to specify a particular Individual or an Involved Party Role played by an Individual. </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedPartyName_TO">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="middleNames" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The additional names given to an Individual, usually at birth, and which appear sequentially between the first name and last name.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="prefixTitle" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The honorifics or titles that precede the name when addressing an Individual in polite, somewhat formal circumstances.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="suffixTitle" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The titles, qualifications, or positions that follow the &lt;Individual&gt;'s name when addressing her formally or professionally, usually when writing.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="firstName" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The Individual's name normally preceding the last name and typically used to refer to the person in informal circumstances. For Example: John, Mary</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="lastName" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The part of a Individual's name arising from family identifications. e.g. Murphy.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedPartyName_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a name associated with an Involved Party. Multiple names are possible both concurrently and over time, varying by the use of the name such as the birth name or marriage name.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="nameText" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>Name text</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="description" type="pdt:Text"/>
          <xsd:element minOccurs="0" name="startDate" type="pdt:Date"/>
          <xsd:element minOccurs="0" name="endDate" type="pdt:Date"/>
          <xsd:element minOccurs="0" name="aliasType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="usage" type="pdt:Reference"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Organization_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party that is a group of Individuals bound by a common purpose. This includes commercial Organizations such as limited companies, publicly quoted multinationals, subsidiaries, etc. Organizations include Financial Organizations that provides products and services related to the financial services sector of the economy. Examples of such products and services include accepting deposits, making of loans, exchanging foreign currency, providing bill finance, handling foreign trade, managing investments and financing corporations. These financial organizations include the various types of banks (e.g.: retail banks, merchant banks, accepting houses, discount houses, foreign banks), building societies, pension funds, unit trusts, investment trusts and insurance companies. Financial organizations are either recognized as such by law or are regulated by a self regulating organization.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedParty_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="incorporationDate" type="pdt:Date">
            <xsd:annotation>
              <xsd:documentation>Identifies the date of the Incorporation of the Organization </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="isIncorporatedIn" type="crfpTO:GeographicArea_TO"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasTradingAddress" type="crfpTO:PostalAddress_TO">
            <xsd:annotation>
              <xsd:documentation>Attribute of the relationship between an Organization and a PostalAddress where the address is registered as a trading address for the Organization. Creation Date: 06/04/2018 Last Change Modeler: Julie Williamson Initiative: Party MDM</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="organizationClassificationType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="tradeStartMonth" type="pdt:Number">
            <xsd:annotation>
              <xsd:documentation>Month the Organization started trading.  Facilitates the requirement to break the trading start date into separate Month and Year elements.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="tradeStartYear" type="pdt:Number">
            <xsd:annotation>
              <xsd:documentation>Year the Organization started trading.  Facilitates the requirement to break the trading start date into separate Month and Year elements.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="fiscalYearEnd" type="pdt:Number"/>
          <xsd:element minOccurs="0" name="areaOfOperation" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="hasInternationalTrade" type="pdt:Reference"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="OrganizationUnit_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party that is a component or subdivision of an Organization established for the purpose of performing discrete functional responsibilities. This typically represents the Organizational structure of the modeled Organization including sections, departments, district offices, projects, and employment positions.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedParty_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="parentOrganization" type="crfpTO:Organization_TO">
            <xsd:annotation>
              <xsd:documentation>Returns the parent Organization for given Organization Unit. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedPartyAssociation_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies additional details about the association of one Involved Party to another Involved Party, for example, the delegated duty.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="associationStart" type="pdt:DateTime"/>
          <xsd:element minOccurs="0" name="associatedInvolvedParty" type="crfpTO:InvolvedParty_TO"/>
          <xsd:element minOccurs="0" name="associationEnd" type="pdt:DateTime"/>
          <xsd:element minOccurs="0" name="associationType" type="pdt:Reference"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="EducationCourse_TO">
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="startDate" type="pdt:Date"/>
          <xsd:element minOccurs="0" name="endDate" type="pdt:Date"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Individual_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party that is a natural person who is of interest to the modeled organization.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedParty_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="birthDate" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The birth date of the Individual</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="gender" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The Individual's sex or gender.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="maritalStatus" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="deathDate" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The date of the Individual's death. IBM Unique ID: IDM09020</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="occupation" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="birthPlace" type="pdt:String"/>
          <xsd:element minOccurs="0" name="hasBirthCountry" type="pdt:Reference"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasCitizenships" type="crfpTO:NationalRegistration_TO"/>
          <xsd:element minOccurs="0" name="additionalCitizenships" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>Identifies whether the &lt;Individual&gt; is a citizen of multiple countries and that the number of countries exceeds that in which RBS records the details. Note: In the current Core provider implementation, this indicator represents the situation where there are more than 4 countries of citizenship</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="primaryNationalityRegistration" type="crfpTO:NationalRegistration_TO"/>
          <xsd:element minOccurs="0" name="isStaff" type="pdt:String"/>
          <xsd:element minOccurs="0" name="employmentStatus" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="isHighNetWorth" type="pdt:String"/>
          <xsd:element minOccurs="0" name="specialCreditIndicatorType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="mainSourceOfWealth" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="mainSourceOfIncome" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="consentToDataUsage" type="pdt:String"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="records" type="crfpTO:EducationCourse_TO"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedParty_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Role Player that is any participant that may have contact with, or that is of interest to the modeled organization, and about which the Financial Institution wishes to maintain information. This includes the modeled organization itself.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:RolePlayer_TO">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasForName" type="crfpTO:InvolvedPartyName_TO">
            <xsd:annotation>
              <xsd:documentation>name of the party</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="isSensitive" type="pdt:String"/>
          <xsd:element minOccurs="0" name="hasLegalAddress" type="crfpTO:PostalAddress_TO"/>
          <xsd:element minOccurs="0" name="hasPartyType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The PartyType of the Involved Party</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasInvolvedPartyAssociation" type="crfpTO:InvolvedPartyAssociation_TO"/>
          <xsd:element minOccurs="0" name="hasRiskCountry" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="residesAt" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Specifies the Country the Involved Party resides at, for example John Doe resides in Canada.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasTaxRegistrations" type="crfpTO:NationalRegistration_TO"/>
          <xsd:element minOccurs="0" name="isPoliticallyExposed" type="pdt:String"/>
          <xsd:element minOccurs="0" name="isPrivateBankParty" type="pdt:String"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
</xsd:schema>


---------------------


PrimitiveDatatypes.xsd

<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" version="RBS_20180711_Baseline" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/">
  <xsd:simpleType name="String">
    <xsd:annotation>
      <xsd:documentation>A string of characters (optionally containing blanks) for which a maximum length can be specified.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string"/>
  </xsd:simpleType>
  <xsd:complexType name="AddressComponent">
    <xsd:annotation>
      <xsd:documentation>An individual component of a postal address e.g. City, Zip Code. Inherits from Reference, which specifies type (City, Address Line 1 , PostCode ...)
</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:Reference">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" name="address" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The address content populating the specified PostalAddressComponentType</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:simpleType name="Time">
    <xsd:annotation>
      <xsd:documentation>An indication of a particular time in a day expressed with a maximum precision of one millisecond.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:time"/>
  </xsd:simpleType>
  <xsd:simpleType name="Text">
    <xsd:annotation>
      <xsd:documentation>A string of characters (optionally containing blanks) for which a maximum length cannot realistically be fixed.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string"/>
  </xsd:simpleType>
  <xsd:simpleType name="Number">
    <xsd:annotation>
      <xsd:documentation>A numeric value capable of holding a real number, not capable of holding a fractional or decimal value.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:integer"/>
  </xsd:simpleType>
  <xsd:simpleType name="ReturnCode">
    <xsd:annotation>
      <xsd:documentation>Identifies an opaque result handle defined to be zero for a successful return from a function and nonzero if error or status information is returned.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:integer"/>
  </xsd:simpleType>
  <xsd:simpleType name="Boolean">
    <xsd:annotation>
      <xsd:documentation>Boolean indicates a logical TRUE or FALSE condition.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:boolean"/>
  </xsd:simpleType>
  <xsd:complexType name="CurrencyAmount">
    <xsd:annotation>
      <xsd:documentation>A monetary amount including the Currency Type. Inherits from Amount, where the KeyValuePair identifies the Unit of Measure ClassificationScheme / Value for CurrencyType / Currency.  E.g. ISO4217 / GBP
</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:Amount">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="numberOfDecimalPlaces" type="pdt:Number"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:simpleType name="TimePeriod">
    <xsd:annotation>
      <xsd:documentation>A duration of time expressed in years, months, days, hours, minutes, and seconds.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:duration"/>
  </xsd:simpleType>
  <xsd:simpleType name="Percentage">
    <xsd:annotation>
      <xsd:documentation>A ratio, usually expressed as a number of units in 100. Strictly speaking a value outside of the range 0 to 100 is invalid, but these values are common.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:decimal"/>
  </xsd:simpleType>
  <xsd:simpleType name="Date">
    <xsd:annotation>
      <xsd:documentation>An indication of a particular day in the Gregorian calendar.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:date"/>
  </xsd:simpleType>
  <xsd:simpleType name="DateTime">
    <xsd:annotation>
      <xsd:documentation>An indication of a particular date and time expressed with a precision of one millisecond.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:dateTime"/>
  </xsd:simpleType>
  <xsd:simpleType name="Decimal">
    <xsd:annotation>
      <xsd:documentation>A numeric value that is not restricted to integer values and has a decimal point denoting fractional units.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:decimal"/>
  </xsd:simpleType>
  <xsd:simpleType name="Base64">
    <xsd:restriction base="xsd:base64Binary"/>
  </xsd:simpleType>
  <xsd:simpleType name="Byte">
    <xsd:annotation>
      <xsd:documentation>An 8-bit integer that is not signed</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:byte"/>
  </xsd:simpleType>
  <xsd:simpleType name="Identifier">
    <xsd:annotation>
      <xsd:documentation>A numeric value capable of holding a real number that uniquely identifies an instance.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:unsignedInt"/>
  </xsd:simpleType>
  <xsd:complexType name="Property">
    <xsd:annotation>
      <xsd:documentation>Represents key-value pair that allows for attachment of additional attributes to request header (and potentially also on other business objects (dynamic properties/hash table concept).</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:PropertyVariant">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="name" type="xsd:string">
            <xsd:annotation>
              <xsd:documentation>The name of a PropertyVariant.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="PropertyStructure">
    <xsd:sequence>
      <xsd:element maxOccurs="unbounded" name="properties" type="pdt:Property"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="NAPParameters">
    <xsd:annotation>
      <xsd:documentation>NAP Specific request parameters. Used by ATP operations establishFundsAvailability and establishFundsReservation. Complex Type made to consolidate unmodelled NAP elements in SDM
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="transactionFundsCode" type="pdt:Reference"/>
      <xsd:element name="transactionFundsCodeQualifier" type="pdt:Reference"/>
      <xsd:element name="eventType" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ObjectReference">
    <xsd:annotation>
      <xsd:documentation>Identifier of the corresponding business object. Multiple ObjectReferences may identify a single object. ObjectReferences contain a context that describes the type and governance of the identifier instance.
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="identifier" type="pdt:String"/>
      <xsd:element name="context" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="description" type="pdt:Text"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="extendedProperties" type="pdt:PropertyVariant">
        <xsd:annotation>
          <xsd:documentation>Generic element to facilitate technical extensions to the Business Model. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Binary">
    <xsd:annotation>
      <xsd:documentation>A finite sequence of bytes. The definition consists of two logical elements: binary data and binary data length. Inherits from KeyValuePair, which specifies a ClassificationScheme and Value identifying theContentType.  E.g. a Scheme of MimeTypes and a Value of aiff
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="binaryData" type="xsd:byte">
        <xsd:annotation>
          <xsd:documentation>The data contained in the type</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="length" type="xsd:integer">
        <xsd:annotation>
          <xsd:documentation>The length of data contained in this type
</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="binaryType" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="LifecycleStatus">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="status" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="effectiveDate" type="pdt:DateTime"/>
      <xsd:element minOccurs="0" name="endDate" type="pdt:DateTime"/>
      <xsd:element minOccurs="0" name="priorStatus" type="pdt:LifecycleStatus"/>
      <xsd:element minOccurs="0" name="plannedStatus" type="pdt:LifecycleStatus"/>
      <xsd:element minOccurs="0" name="statusReason" type="pdt:Reference">
        <xsd:annotation>
          <xsd:documentation>Identifies the different types of reasons that are the rationale for a LifecycleStatus current status.
</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="PropertyVariant">
    <xsd:annotation>
      <xsd:documentation>Identifies a generic structure that is capable of holding multiple types of data, which is stored in an independent format within the type.
</xsd:documentation>
    </xsd:annotation>
    <xsd:choice>
      <xsd:element minOccurs="0" name="amount" type="pdt:Amount"/>
      <xsd:element minOccurs="0" name="structure" type="pdt:PropertyStructure"/>
      <xsd:element minOccurs="0" name="binary" type="pdt:Binary"/>
      <xsd:element minOccurs="0" name="_boolean" type="pdt:Boolean"/>
      <xsd:element minOccurs="0" name="_byte" type="pdt:Byte"/>
      <xsd:element minOccurs="0" name="currencyAmount" type="pdt:CurrencyAmount"/>
      <xsd:element minOccurs="0" name="date" type="pdt:Date"/>
      <xsd:element minOccurs="0" name="dateTime" type="pdt:DateTime"/>
      <xsd:element minOccurs="0" name="decimal" type="pdt:Decimal"/>
      <xsd:element minOccurs="0" name="identifier" type="pdt:Identifier"/>
      <xsd:element minOccurs="0" name="number" type="pdt:Number"/>
      <xsd:element minOccurs="0" name="percentage" type="pdt:Percentage"/>
      <xsd:element minOccurs="0" name="reference" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="string" type="pdt:String"/>
      <xsd:element minOccurs="0" name="time" type="pdt:Time"/>
      <xsd:element minOccurs="0" name="timePeriod" type="pdt:TimePeriod"/>
      <xsd:element minOccurs="0" name="base64" type="xsd:base64Binary"/>
      <xsd:element minOccurs="0" name="objectReference" type="pdt:ObjectReference"/>
    </xsd:choice>
  </xsd:complexType>
  <xsd:complexType name="fileLocation">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="fileLocation" type="pdt:String"/>
      <xsd:element minOccurs="0" name="fileAddressType" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="accountingTransactionParameter">
    <xsd:sequence>
      <xsd:element name="instructionIdentifer" type="pdt:ObjectReference"/>
      <xsd:element name="transactionIdentifer" type="pdt:ObjectReference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ObjectType">
    <xsd:complexContent>
      <xsd:extension base="pdt:Reference">
        <xsd:sequence>
          <xsd:element name="operationalNature" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Indicates whether the particular BMO instance is created for Production, Test or Training purposes.
</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="LanguageSpecificDescriptor">
    <xsd:annotation>
      <xsd:documentation>Language specific name and optional description for an Object.  The inherited KeyValuePair identifies the language meta-data managed as ReferenceData</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="name" type="xsd:string"/>
      <xsd:element minOccurs="0" name="description" type="xsd:string"/>
      <xsd:element name="language" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Amount">
    <xsd:annotation>
      <xsd:documentation>A numeric count including units, such as litres, inches, or kilometres per litre. An example would be 150 km/h.
Includes a ReferenceIdentifier theUnit, which identifies a specific ClassificationScheme and Value representing theUnit. E.g. a Scheme for Volumetric Units of Measure and a Value of Liters
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="amount" type="xsd:decimal">
        <xsd:annotation>
          <xsd:documentation>The amount being measured</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="unitOfMeasure" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="BalanceType">
    <xsd:annotation>
      <xsd:documentation>BalanceDerivationType combined with PointBalanceType as the basis for retrieval of AccountingUnit by Type operation.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:Reference">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="pointBalanceType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Distinguishes between Point Balances according to whether they are associated with the beginning, middle or end of a specified interval of time.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="accountingEffectType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>A Classification Scheme that distinguishes between Posting Entries based on whether they increase or decrease the balance of a particular type of Accounting Unit.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="TransactionHistoryFilter">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="transactionType" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="postingStatus" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="startDate" type="pdt:Date"/>
      <xsd:element minOccurs="0" name="endDate" type="pdt:Date"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Reference">
    <xsd:annotation>
      <xsd:documentation>Used extensively for representing the name of a ClassificationScheme.name and ReferenceClassification.code in a managed ReferenceData repository. The managed meta-data referenced by such a Reference attribute instance, is retrievable using CRUD operations on ClassificationScheme and Value </xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="schemeName" type="xsd:string">
        <xsd:annotation>
          <xsd:documentation>Holds the scheme of the ClassificationScheme / Value pair.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="codeValue" type="xsd:string">
        <xsd:annotation>
          <xsd:documentation>Holds the value of a  ClassificationScheme / Value pair.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="description" type="pdt:Text"/>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>


--------

ServiceDefinitions.xsd


<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/Services/Definitions/V03/" version="RBS_20180717_Baseline" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/">
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="ResponseCursor">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="resultSetID" type="pdt:PropertyVariant"/>
      <xsd:element minOccurs="0" name="countReturned" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Number of responses returned</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="maxCount" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Total number of results found</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="SMMValue" type="pdt:Property">
        <xsd:annotation>
          <xsd:documentation>Start reference in result set to return from.  This may be a composite set of properties.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="SMMIndicator" type="pdt:Boolean">
        <xsd:annotation>
          <xsd:documentation>Indicator of more information available</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:simpleType name="NotificationCategory">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between notification according to the status of processing reported.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Error">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting an error during the processing. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Info">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting an information about what happened during the processing.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Warning">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting a warning about what happened during the processing.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Abort">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting that the processing had to be aborted. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Success">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting that the processing had benn succesfully completed.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandRequestcmd">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between request commands according to their nature.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Request">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a request.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Notification">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a notification (one way message). </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Acknowledge"/>
      <xsd:enumeration value="Heartbeat">
        <xsd:annotation>
          <xsd:documentation>To enable service platform heartbeat service</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="ESPHeartbeat">
        <xsd:annotation>
          <xsd:documentation>To enable service platform heartbeat service</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandExceptioncmdStatus">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between exception messages according to the status of processing reported. </xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="NotExecuted">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had not been executed at all.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Failed">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had failed to complete. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandRequestcmdMode">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between request commands according to the response expectations. </xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="OnlyRespondInError">
        <xsd:annotation>
          <xsd:documentation>Identifies a (request) message to expect a response only in the case of error. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="NeverRespond">
        <xsd:annotation>
          <xsd:documentation>Identifies a (request) message not to expect a response at all. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="AlwaysRespond">
        <xsd:annotation>
          <xsd:documentation>Identifies a (request) message to always expect a response. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandResponsecmd">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between response commands according to their nature. </xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Response">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a response. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Notification">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a notification (one way message).</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:complexType name="ProcessingIdentifier">
    <xsd:annotation>
      <xsd:documentation>Represents a system generated (major) transaction identifier assigned to this processing.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="systemId" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Identifies the system initiating the transaction. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="transactionId" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Identifies the transaction.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:simpleType name="CommandResponsecmdStatus">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between response messages according to the status of processing reported.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Succeeded">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had been succesfully completed.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="PartiallySucceeded">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had been partially succesfully completed.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Acknowledged"/>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:complexType name="RequestCursor">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="resultSetID" type="pdt:PropertyVariant"/>
      <xsd:element minOccurs="0" name="countRequested" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Maximum number of responses to be returned</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="maxCount" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Default maximum number to return if countRequested not specified</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="SMMValue" type="pdt:Property">
        <xsd:annotation>
          <xsd:documentation>Start reference in result set to return from.  This may be a composite set of properties.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="SMMIndicator" type="pdt:Boolean">
        <xsd:annotation>
          <xsd:documentation>Indicator of more information available</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ResponseHeader">
    <xsd:annotation>
      <xsd:documentation>Represent the header information returned with each response message.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="responseId" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Represents the integration system (e.g. DataPower) generated (major) transaction identifier, which identify the system sending the message and system generated ID (number) for the message. Used mostly only for logging/tracking purposes.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="operatingBrand" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the operating brand (inside RBS) that has sent this command. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="refRequestIds" type="sdef:ProcessingIdentifier"/>
      <xsd:element minOccurs="0" name="cmdType" type="sdef:CommandResponsecmd">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the type of the command (can be Response or Notification the case of RequestHeader).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdStatus" type="sdef:CommandResponsecmdStatus">
        <xsd:annotation>
          <xsd:documentation>Specifies the status of the request processing on the provider side (success/failure/unknown).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="cmdNotifications" type="sdef:CommandNotification">
        <xsd:annotation>
          <xsd:documentation>Contains the list of Commands (if any) optionally returned with the response (informing about potential business errors that occurred during the request processing).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Exception">
    <xsd:annotation>
      <xsd:documentation>Represent the Service/Message Error object that can be returned as an optional service/message invocation response.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="responseId" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Represents the integration system (e.g. DataPower) generated (major) transaction identifier, which identify the system sending the message and system generated ID (number) for the message. Used mostly only for logging/tracking purposes.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="refRequestIds" type="sdef:ProcessingIdentifier"/>
      <xsd:element minOccurs="0" name="operatingBrand" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the operating brand (inside RBS) that has sent this command. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="serviceName" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Holds the name of the service to whose operation this SOAFault object is response to.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="operationName" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Holds the name of the service operation to which this SOAFault object is response to.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdStatus" type="sdef:CommandExceptioncmdStatus"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="cmdNotifications" type="sdef:CommandNotification"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="CommandNotification">
    <xsd:annotation>
      <xsd:documentation>Specifies the CommandNotification's category (Error/Warning/Info/...).</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="returnCode" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the ESB CommandNotification's error code.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="category" type="sdef:NotificationCategory">
        <xsd:annotation>
          <xsd:documentation>Represents a system notification that can be received as part of a CommandNotification. This is the representation of a notification triggered by a single system in reaction for receiving the service request.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="description" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Holds the ESB CommandNotification's textual description.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="timestamp" type="pdt:DateTime">
        <xsd:annotation>
          <xsd:documentation>Holds the ESB CommandNotification's timestamp - when it was created.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="systemNotifications" type="sdef:SystemNotification">
        <xsd:annotation>
          <xsd:documentation>Contains the (optional) list of underlying SystemNotifications that resulted in/are the reason for in this CommandNotification</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="SystemNotification">
    <xsd:annotation>
      <xsd:documentation>Represents a system notification that can be received as part of a CommandNotification. This is the representation of a notification triggered by a single system in reaction for receiving the service request.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="returnCode" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the SystemNotification's error code.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="category" type="sdef:NotificationCategory">
        <xsd:annotation>
          <xsd:documentation>Specifies the SystemNotification's category (Error/Warning/Info/...).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="description" type="pdt:Text">
        <xsd:annotation>
          <xsd:documentation>Specifies the text of the SystemMessage.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="processingId" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Represents the 'transaction identifier' assigned to the processing by a provider integration system.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="RequestHeader">
    <xsd:annotation>
      <xsd:documentation>Represent the header information send with each request message.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="operatingBrand" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the operating brand (inside RBS) that has sent this command.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="requestIds" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Specifies the processing 'transaction Ids', assigned to the processing by individual service invocation layers - used mostly for logging/tracking.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdType" type="sdef:CommandRequestcmd">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the type of the command (can be Request or Notification the case of RequestHeader).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdMode" type="sdef:CommandRequestcmdMode">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the request is expecting a response to be sent back (under which circumstance a response is expected)</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="echoBack" type="xsd:boolean">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the response should echo back the request's data.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>


