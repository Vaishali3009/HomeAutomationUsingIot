Working WSDL :-   http://localhost:8080/ALL/CUSTFORPAYMT040.wsdl

Expected Working WSDL :-   http://localhost:8080/ALL/CUSTFORPAYMT040/01.wsdl



package com.rbs.bdd.infrastructure.config;

import com.rbs.bdd.application.exception.SchemaValidationException;
import com.rbs.bdd.application.exception.XsdSchemaLoadingException;
import com.rbs.bdd.infrastructure.soap.interceptor.AccountSchemaValidationInterceptor;
import com.rbs.bdd.infrastructure.soap.interceptor.CustomerSchemaValidationInterceptor;
import com.rbs.bdd.infrastructure.soap.interceptor.TransactionIdInterceptor;
import com.rbs.bdd.util.SoapInterceptorUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
@Slf4j
public class SoapWebServiceConfig extends WsConfigurerAdapter {
    @Autowired
    private TransactionIdInterceptor transactionIdInterceptor;


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
        return new ServletRegistrationBean<>(servlet, "/ALL/*");
    }

    /**
     * Adds a custom interceptor for schema validation. This interceptor validates incoming SOAP
     * messages against the configured XSD schema.
     *
     * @param interceptors list of interceptors to which this validation interceptor is added
     */
    @Override
    public void addInterceptors(List<EndpointInterceptor> interceptors) {

        log.info(" Adding Interceptors");

        CustomerSchemaValidationInterceptor customerRetrievalInterceptor = new CustomerSchemaValidationInterceptor();
        customerRetrievalInterceptor.setValidateRequest(true);   // Validate incoming SOAP requests
        customerRetrievalInterceptor.setValidateResponse(false); // Do not validate outgoing responses
        try {
            customerRetrievalInterceptor.setXsdSchemaCollection(updateCustomerRetrievalXsd());
        } catch (Exception e) {
            throw new XsdSchemaLoadingException("Request XML Schema Validation failed", e);
        }
        interceptors.add(customerRetrievalInterceptor);

        AccountSchemaValidationInterceptor validatingInterceptor = new AccountSchemaValidationInterceptor();
        validatingInterceptor.setValidateRequest(true);   // Validate incoming SOAP requests
        validatingInterceptor.setValidateResponse(false); // Do not validate outgoing responses
        try {
            validatingInterceptor.setXsdSchemaCollection(updateContactXsd());
        } catch (Exception e) {
            throw new XsdSchemaLoadingException("Request XML Schema Validation failed", e);
        }
        interceptors.add(validatingInterceptor);
        interceptors.add(transactionIdInterceptor);


    }

    /**
     * Publishes a WSDL endpoint based on the `ArrValidationForPaymentParameters.xsd` file.
     * This exposes the WSDL dynamically under /ws/ArrValidationForPaymentParameters.wsdl
     *
     * @return a configured WSDL definition bean
     * @throws SchemaValidationException if XSD loading fails
     */
    @Bean(name = "ARRVALPYMT040")
    public DefaultWsdl11Definition accountValidationWSDL() throws SchemaValidationException {
        log.info("Account Validation Endpoint is invoked");
         return  SoapInterceptorUtils.buildWsdlDefinition(
                "IArrValidationForPayment",
                "http://com/rbsg/soa/C040PaymentManagement/ArrValidationForPayment/V01/",
                "/ALL/ARRVALPYMT040/01",
                updateContactXsd()
        );
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
        return SoapInterceptorUtils.loadSchema("xsd/account-validation/ArrValidationForPaymentParameters.xsd");

    }


    /**
     * Publishes a WSDL endpoint based on the `CustomerRetrievalForPaymentParameters.xsd` file.
     * This exposes the WSDL dynamically under /ws/CustomerRetrievalForPaymentParameters.wsdl
     *
     * @return a configured WSDL definition bean
     * @throws SchemaValidationException if XSD loading fails
     */
    @Bean(name = "CUSTFORPAYMT040")
    public DefaultWsdl11Definition customerRetrievalWSDL() throws SchemaValidationException {
        log.info("Customer Retrieval Endpoint is invoked");
        return  SoapInterceptorUtils.buildWsdlDefinition(
                "ICustomerRetrievalForPayment",
                "http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/",
                "/ALL/CUSTFORPAYMT040/01",
                updateCustomerRetrievalXsd()
        );
    }


    /**
     * Loads the primary XSD schema (`CustomerRetrievalForPaymentParameters.xsd`) from the classpath
     * and enables inlining for WSDL generation and schema validation.
     *
     * @return an XsdSchemaCollection used for both WSDL publishing and request validation
     * @throws XsdSchemaLoadingException if schema loading fails due to I/O or classpath errors
     */
    @Bean
    public XsdSchemaCollection updateCustomerRetrievalXsd() {
        return SoapInterceptorUtils.loadSchema("xsd/customer-retrieval/CustomerRetrievalForPaymentParameters.xsd");
    }


}


-----------------------
package com.rbs.bdd.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WsRedirectConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/ALL/ARRVALPYMT040/01.wsdl")
                .setViewName("forward:/ALL/ARRVALPYMT040.wsdl");
        registry.addViewController("/ALL/CUSTFORPAYMT040/01.wsdl")
                .setViewName("forward:/ALL/CUSTFORPAYMT040.wsdl");

    }
}




