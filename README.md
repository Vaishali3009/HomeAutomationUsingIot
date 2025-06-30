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
 * Service implementation for handling customer retrieval logic via SOAP.
 * <p>
 * The class validates incoming request data and returns a static or error SOAP XML response
 * based on IBAN/account matches in DB or hardcoded list.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomerRetrievalService implements RetrieveCustomerPort {

    private final CustomerRepository repository;
    private static final String STATIC_RESPONSE_PATH = "static-response/customer-retrieval/success-response.xml";

    /**
     * Schema validation is handled by Spring WS automatically.
     *
     * @param request the validated SOAP request
     */
    @Override
    public void validateSchema(RetrievePrimaryCustomerForArrRequest request) {
        log.info("Schema validated successfully by Spring WS.");
    }

    /**
     * Processes customer retrieval logic.
     * Attempts DB match, fallback to hardcoded match, else returns error.
     *
     * @param request SOAP request
     * @param message SOAP response message
     */
    @Override
    public void retrieveCustomer(RetrievePrimaryCustomerForArrRequest request, WebServiceMessage message) {
        try {
            RequestParams params = extractParams(request);
            XPath xpath = XPathFactory.newInstance().newXPath();
            Document responseDoc = handleCustomerRetrieval(params, xpath);
            writeResponseToSoapMessage(message, responseDoc);
        } catch (Exception e) {
            log.error("Customer retrieval failed", e);
            throw new CustomerRetrievalException("Customer retrieval failed", e);
        }
    }

    /**
     * Handles customer lookup logic from DB and hardcoded list with error fallback.
     */
    private Document handleCustomerRetrieval(RequestParams params, XPath xpath)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

        Optional<ErrorDetail> error = determineCustomerRetrievalError(params);
        if (error.isPresent()) {
            return buildErrorResponse(error.get(), xpath, params.originalTxnId(),
                    ServiceConstants.Paths.ERROR_XML_PATH_FOR_CUSTOMER_RETRIEVAL);
        }

        Optional<CustomerData> dbResult = repository.findByAccountNo(params.identifier());
        if (dbResult.isPresent() && dbResult.get().getAccountType().equals(params.codeValue())) {
            log.info("DB match found for IBAN: {}", params.identifier());
            CustomerInfo customer = new CustomerInfo(
                    dbResult.get().getPrefixType(),
                    dbResult.get().getFirstName(),
                    dbResult.get().getLastName()
            );
            return buildSuccessResponse(xpath, customer);
        }

        CustomerNameMapping matched = CustomerNameMapping.fromIdentifier(params.identifier());
        if (matched != null) {
            log.info("Hardcoded account matched for IBAN: {}", params.identifier());
            CustomerInfo customer = new CustomerInfo(
                    matched.getPrefixType(),
                    matched.getFirstName(),
                    matched.getLastName()
            );
            return buildSuccessResponse(xpath, customer);
        }

        log.error("Customer not found for IBAN: {}", params.identifier());
        return buildErrorResponse(
                ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail(), xpath,
                params.originalTxnId(), ServiceConstants.Paths.ERROR_XML_PATH);
    }

    /**
     * Builds a success response document from the static XML and populates name fields.
     */
    private Document buildSuccessResponse(XPath xpath, CustomerInfo customer)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

        Document responseDoc = loadAndParseXml(STATIC_RESPONSE_PATH);
        updateName(responseDoc, xpath, customer);
        return responseDoc;
    }

    /**
     * Builds an error response document by loading the template and injecting error fields.
     */
    private Document buildErrorResponse(ErrorDetail detail, XPath xpath, String txnId, String path)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

        Document doc = loadAndParseXml(path);
        applyErrorResponse(doc, xpath, detail, txnId);
        return doc;
    }

    /**
     * Populates name fields in the static XML response.
     */
    private void updateName(Document doc, XPath xpath, CustomerInfo customer) throws XPathExpressionException {
        updateText(xpath, doc, XPATH_PREFIX_TYPE, customer.prefixType());
        updateText(xpath, doc, XPATH_FIRST_NAME, customer.firstName());
        updateText(xpath, doc, XPATH_LAST_NAME, customer.lastName());
    }

    /**
     * Performs error checks based on prefix, length, or modulus check.
     */
    private Optional<ErrorDetail> determineCustomerRetrievalError(RequestParams param) {
        Map<ValidationErrorType, ErrorDetail> errorMap = Map.of(
                ValidationErrorType.INVALID_PREFIX, ErrorConstants.ERR_UBAN_GB.detail(),
                ValidationErrorType.INVALID_LENGTH, ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail(),
                ValidationErrorType.INVALID_MODULUS, ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail()
        );

        return ValidationUtils.validateAccount(param, errorMap, this::isUbanValid, "CustomerRetrieval");
    }

    /**
     * Validates UBAN by matching last 14 digits against known IBAN list.
     */
    private boolean isUbanValid(String identifier) {
        return ServiceConstants.IBANs.ALL_IBANS.stream()
                .map(this::extractLast14Digits)
                .anyMatch(suffix -> suffix.equals(identifier));
    }

    /**
     * Returns last 14 digits from full IBAN.
     */
    private String extractLast14Digits(String iban) {
        return iban.length() >= 14 ? iban.substring(iban.length() - 14) : "";
    }

    /**
     * Loads an XML file from the classpath and parses it into a DOM document.
     */
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

    /**
     * Updates the text content of a node based on an XPath expression.
     */
    private void updateText(XPath xpath, Document doc, String path, String value) throws XPathExpressionException {
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null && value != null) {
            node.setTextContent(value);
        }
    }

    /**
     * Extracts core request values into a simple parameter container.
     */
    private RequestParams extractParams(RetrievePrimaryCustomerForArrRequest request) {
        return new RequestParams(
                request.getArrangementIdentifier().getIdentifier(),
                request.getArrangementIdentifier().getContext().getCodeValue(),
                request.getRequestHeader().getRequestIds().get(0).getTransactionId(),
                request.getRequestHeader().getRequestIds().get(0).getSystemId()
        );
    }

    /**
     * Record for holding structured customer name details.
     */
    public record CustomerInfo(String prefixType, String firstName, String lastName) {
    }
}
