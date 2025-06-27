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
            logger.info("Error occured while retrieving Customer info: "+ error);
            Document errorDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH_FOR_CUSTOMER_RETRIEVAL);
            applyErrorResponse(errorDoc, xpath, error.get(), params.originalTxnId());
            return errorDoc;
        }
        else {
            CustomerInfo customerData;
            Optional<CustomerData> dbResult = repository.findByAccountNo(params.identifier());
            log.info("Account Number found in database: ");
            log.info("Account Number : "+params.identifier());
            log.info("Searching account in the database");
            if (dbResult.isPresent() && dbResult.get().getAccountType().equals(params.codeValue())) {
                log.info("Account Number and Account Type is matched");
                customerData = new CustomerInfo(
                        dbResult.get().getPrefixType(),
                        dbResult.get().getFirstName(),
                        dbResult.get().getLastName()
                );
                Document responseDoc = loadAndParseXml(STATIC_RESPONSE_PATH);
                updateName(responseDoc, xpath, customerData);
                  logger.info("Returning matched customer response from Database  for IBAN: {}");
                return responseDoc;
            } else if(CustomerNameMapping.fromIdentifier(params.identifier())!=null){
                log.debug("Searching account in the Pre-configured List of Accounts");
                CustomerNameMapping matched = CustomerNameMapping.fromIdentifier(params.identifier());

                    Document responseDoc = loadAndParseXml(STATIC_RESPONSE_PATH);
                    CustomerInfo custData = new CustomerInfo(
                            matched.getPrefixType(), matched.getFirstName(), matched.getLastName()

                    );
                    updateName(responseDoc, xpath, custData);
                    logger.info("Returning matched customer response for IBAN: {}");
                    return responseDoc;

                }
            else {
                logger.error("Customer Not Found");

                Document notFoundDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
                applyErrorResponse(notFoundDoc, xpath, ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail(), params.originalTxnId());
                return notFoundDoc;
            }
        }
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

        if ("Unable To Complete Request".equals(detail.description())){
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC, detail.systemNotificationDesc());
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_CODE, detail.returnCode());
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
