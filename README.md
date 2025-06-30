private Document handleCustomerRetrieval(RequestParams params, XPath xpath)
        throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

    logger.debug("Handle Customer Retrieval");

    Optional<ErrorDetail> error = determineCustomerRetrievalError(params);
    if (error.isPresent()) {
        return buildErrorResponse(error.get(), xpath, params.originalTxnId(),
                ServiceConstants.Paths.ERROR_XML_PATH_FOR_CUSTOMER_RETRIEVAL);
    }

    // 1. Try DB match
    Optional<CustomerData> dbResult = repository.findByAccountNo(params.identifier());
    if (dbResult.isPresent() && dbResult.get().getAccountType().equals(params.codeValue())) {
        logger.info("Account matched in DB for IBAN: {}", params.identifier());
        CustomerInfo customer = new CustomerInfo(
                dbResult.get().getPrefixType(),
                dbResult.get().getFirstName(),
                dbResult.get().getLastName()
        );
        return buildSuccessResponse(xpath, customer);
    }

    // 2. Try hardcoded account match
    CustomerNameMapping matched = CustomerNameMapping.fromIdentifier(params.identifier());
    if (matched != null) {
        logger.info("Account matched in config list for IBAN: {}", params.identifier());
        CustomerInfo customer = new CustomerInfo(
                matched.getPrefixType(),
                matched.getFirstName(),
                matched.getLastName()
        );
        return buildSuccessResponse(xpath, customer);
    }

    // 3. Nothing matched
    logger.error("Customer Not Found for IBAN: {}", params.identifier
    ());
    return buildErrorResponse(
            ErrorConstants.ERR_CUSTOMER_NOT_FOUND.detail(), xpath, params.originalTxnId(),
            ServiceConstants.Paths.ERROR_XML_PATH
    );
}



private Document buildSuccessResponse(XPath xpath, CustomerInfo customer)
        throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

    Document responseDoc = loadAndParseXml(STATIC_RESPONSE_PATH);
    updateName(responseDoc, xpath, customer);
    return responseDoc;
}

private Document buildErrorResponse(ErrorDetail errorDetail, XPath xpath, String txnId, String errorXmlPath)
        throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {

    Document errorDoc = loadAndParseXml(errorXmlPath);
    applyErrorResponse(errorDoc, xpath, errorDetail, txnId);
    return errorDoc;
}

