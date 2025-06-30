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



    private Document handleBusinessValidation(RequestParams params, XPath xpath) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
        log.debug("Checking for the error in the request");
        Optional<ErrorDetail> error = determineError(params);

        if (error.isPresent()) {
            log.info("Business error condition detected: {}", error.get().description());
            Document errorDoc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
            applyErrorResponse(errorDoc, xpath, error.get(), params.originalTxnId());
            return errorDoc;
        }

        Optional<ResponseConfig> config = determineMatchingConfig(params);
        if (config.isPresent()) {
            String bankIdentifier =null;
            log.info("Matched account configuration: {}", config.get());
            Document successDoc = loadAndParseXml("static-response/account-validation/success-response.xml");
            if(params.codeValue().equals(INTL_BANK_ACCOUNT)){
                 bankIdentifier =setBankIdentifier(params);
                if(bankIdentifier!=null)
                {
                    log.info("Bank Identifier Value is "+bankIdentifier);
                    updateSuccessResponse(successDoc, xpath, config.get(), params,  bankIdentifier);
                    return successDoc;
                }
                else{

                    log.warn("Incorrcet Bank Identifier Returning MOD97 failure.");
                    Document mod97Doc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
                    applyErrorResponse(mod97Doc, xpath, ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId());
                    return mod97Doc;
                }
            }
            else {
                updateSuccessResponse(successDoc, xpath, config.get(), params, bankIdentifier);
                return successDoc;
            }
        }

        log.error("No account matched. Returning MOD97 failure.");
        Document mod97Doc = loadAndParseXml(ServiceConstants.Paths.ERROR_XML_PATH);
        applyErrorResponse(mod97Doc, xpath, ErrorConstants.ERR_MOD97_IBAN.detail(), params.originalTxnId());
        return mod97Doc;
    }
