private Document handleBusinessValidation(RequestParams params, XPath xpath) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
    log.debug("Checking for the error in the request");

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
