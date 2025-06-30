Error:-
1.  Method handleBusinessValidation has 37 lines of code (exceeds 25 allowed). Consider refactoring.
2.   Method setBankIdentifier has a Cognitive Complexity of 7 (exceeds 5 allowed). Consider refactoring.
3.   - Method handleBusinessValidation has 37 lines of code (exceeds 25 allowed). Consider refactoring.
     4. Method updateSuccessResponse has 5 arguments (exceeds 4 allowed). Consider refactoring.


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

        Document resultDoc;
        Optional<ErrorDetail> error = determineError(params);

        if (error.isPresent()) {
            log.info("Business error condition detected: {}", error.get().description());
            resultDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
            applyErrorResponse(resultDoc, xpath, error.get(), params.originalTxnId());
            return resultDoc;
        }

        Optional<ResponseConfig> config = determineMatchingConfig(params);
        resultDoc = loadAndParseXml("static-response/account-validation/success-response.xml");

        if (config.isPresent()) {
            ResponseConfig cfg = config.get();
            String bankIdentifier = null;

            log.info("Matched account configuration: {}", cfg);

            if (INTL_BANK_ACCOUNT.equals(params.codeValue())) {
                bankIdentifier = setBankIdentifier(params);
                if (bankIdentifier == null) {
                    log.warn("Incorrect Bank Identifier. Returning MOD97 failure.");
                    resultDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
                    applyErrorResponse(resultDoc, xpath, ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId());
                    return resultDoc;
                }
            }

            updateSuccessResponse(resultDoc, xpath, cfg, params, bankIdentifier);
        } else {
            log.error("No account matched. Returning MOD97 failure.");
            resultDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
            applyErrorResponse(resultDoc, xpath, ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId());
        }

        return resultDoc;
    }

    private String setBankIdentifier(RequestParams params) {
        String bankIdentifier = null;
        String iban=params.identifier();
        try {


            if (iban != null && !iban.isEmpty()) {
                if (iban.contains("NWB")) {
                    bankIdentifier = "278";
                } else if (iban.contains("RBS")) {
                    bankIdentifier = "-365";
                } else if (iban.contains("UBN")) {
                    bankIdentifier = "391";
                }
            }
        } catch (Exception ex) {
            log.info("Bank Identifier not correct");

        }
        return bankIdentifier;
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
    private void updateSuccessResponse(Document doc, XPath xpath, ResponseConfig config, RequestParams p,String bankIdentifier) throws XPathExpressionException {
        log.info("Started Updating the response XML with success values");
        updateText(xpath, doc, "//responseId/systemId", p.systemId());
        updateText(xpath, doc, "//responseId/transactionId", generateTxnId());
        updateText(xpath, doc, "//status", config.accountStatus.getValue());
        updateText(xpath, doc, "//switchingStatus", config.switchingStatus.getValue());
        updateText(xpath, doc, "//modulusCheckStatus/codeValue", config.modulusCheckStatus.getValue());
        if(bankIdentifier!=null)
        {
            updateText(xpath, doc, "//parentOrganization/alternativeIdentifier/identifier",bankIdentifier);

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
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_CODE, errorDetail.returnCode());
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
     * </ul>
     */
     @SuppressWarnings("unused")
    public record ResponseConfig(AccountStatus accountStatus, SwitchingStatus switchingStatus,ModulusCheckStatus modulusCheckStatus) {
     // this record is left without methods or additional logic,as it is only used to group and transport validation results
     }



}
