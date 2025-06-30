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
        if (p.identifier().startsWith("GB")) {
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
            return Optional.of(errorMap.get(ValidationErrorType.INVALID_COUNTRY_CODE));
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


-------------------
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
        Document errorDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
        applyErrorResponse(errorDoc, xpath, detail, txnId);
        return errorDoc;
    }

    private Document buildSuccessResponse(RequestParams params, ResponseConfig config, XPath xpath)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
        Document successDoc = loadAndParseXml("static-response/account-validation/success-response.xml");
        String bankIdentifier = INTL_BANK_ACCOUNT.equals(params.codeValue()) ? resolveBankIdentifier(params.identifier()) : null;

        if (INTL_BANK_ACCOUNT.equals(params.codeValue()) && bankIdentifier == null) {
            return buildErrorResponse(ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId(), xpath);
        }

        updateSuccessResponse(successDoc, xpath, config, params, bankIdentifier);
        return successDoc;
    }

    private String resolveBankIdentifier(String iban) {
        if (iban == null || iban.isEmpty()) return null;
        if (iban.contains("NWB")) return "278";
        if (iban.contains("RBS")) return "-365";
        if (iban.contains("UBN")) return "391";
        return null;
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


-----
updateSuccessResponse 
