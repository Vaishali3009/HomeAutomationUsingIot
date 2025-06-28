@Test
void testHandleRequest_callsSuperIfNamespaceMatches() throws Exception {
    // Prepare dummy SOAP message
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

    // Mock message context and set up getRequest() to return SOAP message
    MessageContext messageContext = mock(MessageContext.class);
    when(messageContext.getRequest()).thenReturn(request);

    // Spy the interceptor
    AccountSchemaValidationInterceptor spyInterceptor = spy(interceptor);

    try (MockedStatic<SoapInterceptorUtils> mockedUtils = mockStatic(SoapInterceptorUtils.class)) {
        mockedUtils.when(() ->
                SoapInterceptorUtils.skipInterceptorIfNamespaceNotMatched(any(), any()))
                .thenReturn(false);

        // No need to stub handleRequest on super — just call it
        boolean result = spyInterceptor.handleRequest(messageContext, new Object());

        assertTrue(result); // If super.handleRequest succeeds
    }
}
