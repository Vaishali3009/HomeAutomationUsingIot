![image](https://github.com/user-attachments/assets/2c8b7602-89c4-4453-b8b2-6313bbf64f99)![image](https://github.com/user-attachments/assets/a6906e2a-cb47-40da-b356-110f08afa96e)# EspSimulatorEngine

EspSimulatorEngine is a SpringBoot-based SOAP web service simulator designed to mimic real-time banking operations for account validation and customer retrieval in payment processing scenarios. The project uses  a hexagonal architecture for clean separation of concerns and supports schema validation, dynamic SOAP response handling, and robust AWS Secret Manager integration.

---

## 🚀 Features

* SOAP endpoints for:
  * Account validation (`/ALL/ARRVALPYMT040/01`)
  * Customer retrieval (`/ALL/CUSTFORPAYMT040/01`)
* XSD Schema Validation using Spring WS Interceptors
* Custom SOAP Fault injection on schema failures
* Dynamic Response Generation via XPath-based DOM manipulation
* Hexagonal Architecture (Ports & Adapters)
* AWS Secrets Manager Integration for secure DB credentials
* Liquibase integration for DB migrations
* Unit-tested interceptors and adapters



##  Architecture


### 1. **Hexagonal Layers**

* **Inbound Port**: `PaymentValidationPort`, `CustomerRetrievalPort`
* **Outbound Port**: `AccountValidationPort`, `RetrieveCustomerPort`
* **Application Services**:

  * `AccountValidationService`
  * `CustomerRetrievalService`
* **Adapter Layer**:

  * `PaymentValidationSoapAdapter` for handling SOAP endpoints

### 2. **Interceptors**

| Interceptor                           | Purpose                                        |
| ------------------------------------- | ---------------------------------------------- |
| `AccountSchemaValidationInterceptor`  | XSD validation for account validation requests |
| `CustomerSchemaValidationInterceptor` | XSD validation for customer retrieval requests |
| `TransactionIdInterceptor`            | Extracts and logs transaction ID from SOAP     |

### 3. **AWS Integration**

* `AwsSecretManagerConfig` + `DatabaseConfig`: fetch DB credentials and configure datasource.

---

##  Flow of Request

1. **SOAP Request Received** → `/ALL/ARRVALPYMT040/01`
2. **Transaction ID Extracted** → Stored in `TransactionIdContext`
3. **Schema Validation** → Via `PayloadValidatingInterceptor`
4. **Adapter Invokes Port** → `PaymentValidationPort`
5. **Service Layer**:

   * Validates IBAN/UBAN length, format
   * Applies Modulus 97 validation
   * Loads  XML response templates
   * Applies XPath transformations (first name, last name, status)
     
6. **Custom Response Injected** → Into `WebServiceMessage`

---

##  Technologies Used

| Category           | Technology                        |
| ------------------ | --------------------------------- |
| Core Framework     | Spring Boot 3.4                   |
| SOAP Support       | Spring Web Services (Spring-WS)   |
| XML Binding        | JAXB                              |
| DB Layer           | JPA, HikariCP, PostgreSQL         |
| DB Migration       | Liquibase                         |
| Secrets Management | AWS Secrets Manager SDK (v2)      |
| Testing            | JUnit 5, Mockito, SaajSoapMessage |
| Logging            | SLF4J, Logback                    |

---

##  Project Structure (Summary)


src/main/java/
├── application/
│   ├── service/
│   ├── port/in/
│   ├── port/out/
│   └── exception/
├── infrastructure/
│   ├── soap/api/
│   ├── soap/interceptor/
│   └── config/
├── util/
│   └── SoapInterceptorUtils.java
├── domain/
│   └── enums/, model/
└── common/
    ├── context/, constants/


---

##  Business Scenarios Covered

### Account Validation

* Invalid IBAN length
* Unsupported country codes
* MOD-97 failure
* Schema-level field validations
* Invalid Bank Identifier
* Invalid UBAN length
* Invalid Start of UBAN Number  

###  Customer Retrieval

* Invalid IBAN length
* Customer account found in the database 
* Customer account configured in the code
* Customer Not Found

---

## 🧪 Test Strategy

| Component                   | Tests                                              |
| --------------------------- | -------------------------------------------------- |
| SOAP Adapter                | `PaymentValidationSoapAdapterTest`                 |
| Account Schema Interceptor  | `AccountSchemaValidationInterceptorTest`           |
| Customer Schema Interceptor | `CustomerRetrievalSchemaValidationInterceptorTest` |

---

## Run Locally


# Build
mvn clean install

# Run
mvn spring-boot:run

# Access WSDLs
http://localhost:8080/ALL/ARRVALPYMT040?wsdl
http://localhost:8080/ALL/CUSTFORPAYMT040?wsdl
