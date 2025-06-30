/**
 * Service responsible for validating account information based on business rules.
 * Responds with either a static success or static error SOAP XML.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountValidationService implements AccountValidationPort {

    @Override
    public void validateSchema(ValidateArrangementForPaymentRequest request) {
        log.info("Schema validation completed by Spring WS.");
    }

    @Override
    public void validateBusinessRules(ValidateArrangementForPaymentRequest request, WebServiceMessage message) {
        try {
            log.info("Starting business rule validation.");
            RequestParams params = extractParams(request);
            XPath xpath = XPathFactory.newInstance().newXPath();
            Document doc = validateAndGenerateResponse(params, xpath);
            writeResponseToSoapMessage(message, doc);
        } catch (Exception ex) {
            log.error("Validation failed", ex);
            throw new AccountValidationException("Validation failed", ex);
        }
    }

    private Document validateAndGenerateResponse(RequestParams params, XPath xpath)
            throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

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

    private void updateSuccessResponse(Document doc, XPath xpath, ResponseConfig config,
                                       RequestParams p, String bankIdentifier)
            throws XPathExpressionException {

        updateText(xpath, doc, "//responseId/systemId", p.systemId());
        updateText(xpath, doc, "//responseId/transactionId", generateTxnId());
        updateText(xpath, doc, "//status", config.accountStatus().getValue());
        updateText(xpath, doc, "//switchingStatus", config.switchingStatus().getValue());
        updateText(xpath, doc, "//modulusCheckStatus/codeValue", config.modulusCheckStatus().getValue());

        if (bankIdentifier != null) {
            updateText(xpath, doc, "//parentOrganization/alternativeIdentifier/identifier", bankIdentifier);
        }
    }

    private void applyErrorResponse(Document doc, XPath xpath, ErrorDetail errorDetail, String txnId)
            throws XPathExpressionException {

        updateText(xpath, doc, ServiceConstants.XPath.XPATH_RESPONSE_ID_TXN_ID, generateTxnId());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_REF_REQUEST_TXN_ID, txnId);
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_CMD_STATUS, "Failed");
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_CMD_DESCRIPTION, errorDetail.description());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_TIMESTAMP, ZonedDateTime.now().toString());
        updateText(xpath, doc, ServiceConstants.XPath.XPATH_RETURN_CODE, errorDetail.returnCode());

        if (errorDetail.systemNotificationDesc() != null) {
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_DESC, errorDetail.systemNotificationDesc());
            updateText(xpath, doc, ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_CODE, errorDetail.returnCode());
        } else {
            Node node = (Node) xpath.evaluate(ServiceConstants.XPath.XPATH_SYS_NOTIFICATION_BLOCK, doc, XPathConstants.NODE);
            if (node != null && node.getParentNode() != null) {
                node.getParentNode().removeChild(node);
            }
        }
    }

    private void updateText(XPath xpath, Document doc, String path, String value) throws XPathExpressionException {
        Node node = (Node) xpath.evaluate(path, doc, XPathConstants.NODE);
        if (node != null && value != null) {
            node.setTextContent(value);
        }
    }

    private Document loadAndParseXml(String path)
            throws ParserConfigurationException, IOException, SAXException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream(path);
        if (stream == null) throw new AccountValidationException("XML not found: " + path);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(stream);
    }

    private Optional<ErrorDetail> determineError(RequestParams p) {
        Map<ValidationErrorType, ErrorDetail> map = Map.of(
                ValidationErrorType.INVALID_PREFIX, ErrorConstants.ERR_DB2_SQL.detail(),
                ValidationErrorType.INVALID_IBAN_LENGTH, ErrorConstants.ERR_INVALID_IBAN_LENGTH.detail(),
                ValidationErrorType.INVALID_UBAN_LENGTH, ErrorConstants.ERR_INVALID_UBAN_LENGTH.detail(),
                ValidationErrorType.INVALID_MODULUS, ErrorConstants.ERR_MOD97_UBAN.detail(),
                ValidationErrorType.INVALID_COUNTRY_CODE, ErrorConstants.ERR_WRONG_COUNTRY_CODE.detail()
        );
        return ValidationUtils.validateAccount(p, map, this::isUbanValid, "AccountValidation");
    }

    private boolean isUbanValid(String identifier) {
        return ServiceConstants.IBANs.ALL_IBANS.stream()
                .map(this::extractLast14Digits)
                .anyMatch(ibanSuffix -> ibanSuffix.equals(identifier));
    }

    private String extractLast14Digits(String iban) {
        return iban.length() >= 14 ? iban.substring(iban.length() - 14) : "";
    }

    private Optional<ResponseConfig> determineMatchingConfig(RequestParams p) {
        Map<String, ResponseConfig> ruleMap = Map.of(
                IBAN_1, new ResponseConfig(DOMESTIC_RESTRICTED, SWITCHED, PASSED),
                IBAN_2, new ResponseConfig(DOMESTIC_RESTRICTED, NOT_SWITCHING, PASSED),
                IBAN_3, new ResponseConfig(DOMESTIC_UNRESTRICTED, SWITCHED, PASSED),
                IBAN_4, new ResponseConfig(DOMESTIC_UNRESTRICTED, NOT_SWITCHING, FAILED)
        );

        return ruleMap.entrySet().stream()
                .filter(e -> p.identifier().equals(e.getKey()) || extractLast14Digits(e.getKey()).equals(p.identifier()))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    private RequestParams extractParams(ValidateArrangementForPaymentRequest request) {
        return new RequestParams(
                request.getArrangementIdentifier().getIdentifier(),
                request.getArrangementIdentifier().getContext().getCodeValue(),
                request.getRequestHeader().getRequestIds().get(0).getTransactionId(),
                request.getRequestHeader().getRequestIds().get(0).getSystemId()
        );
    }

    /**
     * Record that groups response configuration elements.
     */
    public record ResponseConfig(AccountStatus accountStatus, SwitchingStatus switchingStatus, ModulusCheckStatus modulusCheckStatus) {}
}
