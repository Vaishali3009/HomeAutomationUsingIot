CustomerRetrievalForPaymentParameters.xsd



<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" version="RBS_20210325_Baseline" xmlns:crfpSP="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/ServiceParameters/V01/" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/">
  <xsd:import namespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" schemaLocation="CustomerRetrievalForPaymentTransferObjects.xsd"/>
  <xsd:import namespace="http://com/rbsg/soa/Services/Definitions/V03/" schemaLocation="ServiceDefinitions.xsd"/>
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="retrievePrimaryCustomerForArrRequest">
    <xsd:sequence>
      <xsd:element name="requestHeader" type="sdef:RequestHeader"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="processingParameter" type="pdt:Property"/>
      <xsd:element name="arrangementIdentifier" type="pdt:ObjectReference">
        <xsd:annotation>
          <xsd:documentation>Identifier of the account for which the Customer is identified as the Primary Customer (Account Owner).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="RetrievePrimaryCustomerForArrContent">
    <xsd:sequence>
      <xsd:element name="responseHeader" type="sdef:ResponseHeader"/>
      <xsd:element minOccurs="0" name="customer" type="crfpTO:InvolvedParty_TO"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="modifyToken" type="pdt:Property"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="retrievePrimaryCustomerForArrResponse">
    <xsd:sequence>
      <xsd:choice>
        <xsd:element name="response" type="crfpSP:RetrievePrimaryCustomerForArrContent"/>
        <xsd:element name="exception" type="sdef:Exception"/>
      </xsd:choice>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>

--------------------------------------------------------------

CustomerRetrievalForPaymentTransferObjects.xsd


<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" version="RBS_20210325_Baseline" xmlns:crfpTO="http://com/rbsg/soa/C040PaymentManagement/CustomerRetrievalForPayment/V01/TransferObjects/V01/" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/">
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="BaseTransferObject">
    <xsd:sequence>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="extendedProperties" type="pdt:Property"/>
      <xsd:element minOccurs="0" name="lastUpdateToken" type="pdt:PropertyVariant">
        <xsd:annotation>
          <xsd:documentation>Datetime for objects that require optimistic locking on update.  The datetime retrieved is passed back on the update operation and validated against the last updated datetime stored for the object.  If they are the same, the update can go ahead.  If not, another update has occurred in the interim and the update is rejected.

As this is on the BaseTransferObject, it can be used selectively for those objects within a retrieve and update operation response / request parameter set, that require such optimistic locking.  This a a set on BMOs and the constituent dependent types, can be used to form a set of lock tokens.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ContactPoint_TO">
    <xsd:annotation>
      <xsd:documentation>The method and destination of a communication contact with a Role Player. This relates to specific communication media: Postal Address, Telephone Number, Electronic Address, Care Of Address </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="priorityLevel" type="pdt:Number">
            <xsd:annotation>
              <xsd:documentation>The relative priority level of one Contact Point over another.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="usage" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The context in which a Role Player uses this Contact Point. eg Primary Residence, Work etc</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasComponent" type="pdt:AddressComponent">
            <xsd:annotation>
              <xsd:documentation>Individual components of a postal address e.g. City, PostCode etc</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="lifecycleStatus" type="pdt:LifecycleStatus">
            <xsd:annotation>
              <xsd:documentation>Lifecycle status of the Contact Point e.g Active, Inactive etc </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="contactPointType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Identifies the type of Contact Point under consideration eg Postal Address, Telephone number etc </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="PostalAddress_TO">
    <xsd:annotation>
      <xsd:documentation>An address used for the delivery of letters and packages by an external mailing or package service, at a place where the recipient usually lives or works. The structure of a postal address depends on the country of the postal address, for this reason a Postal Address is made up of a number of Postal Address Components. </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:ContactPoint_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="postalCodeExemptionReason" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The exempt type of the Postal Address, which indicates whether the postal address is exempted in having a Postal Code.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="GeographicArea_TO">
    <xsd:complexContent>
      <xsd:extension base="crfpTO:ClassificationValue_TO"/>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="ClassificationValue_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a grouping of Business Model Objects, for example; Single Males Under 30, Married People over 50, etc... A Classification Value can be further partitioned into several sub-classifications according to different criteria, each of which is represented in turn by a Classification Scheme.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="schemeName" type="pdt:String"/>
          <xsd:element minOccurs="0" name="codeValue" type="pdt:String"/>
          <xsd:element minOccurs="0" name="name" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The word or phrase that identifies (but not uniquely) the classification value.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="shortName" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>An abridged version of classificationValue name Example: For retrieving job title reference data, If the name of the value is AGRICULTURAL WORKER, the shortName is AG</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="ConditionContext_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies the &lt;Business&gt; to which a &lt;Condition&gt; relates</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="priority" type="pdt:String"/>
          <xsd:element minOccurs="0" name="occurrenceNumber" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>A reference number which signifies the occurrence of the Condition applying to the product Arrangement </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="startDate" type="pdt:DateTime">
            <xsd:annotation>
              <xsd:documentation>The date on which this Condition becomes appicable to the ProductArrangement.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="endDate" type="pdt:Date">
            <xsd:annotation>
              <xsd:documentation>The date from when this Condition is no longer applicable to the ProductArrangement. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Condition_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies the specific requirements that pertain to how the business of the modeled organization is conducted and includes information such as prerequisite or qualification criteria and restrictions or limits associated with the requirements. Conditions can apply to various aspects of a Financial Institution's operations, such as the sale and servicing of Products or the determination of eligibility to purchase a product.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="name" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The word or phrase used to identify (but not uniquely) the Condition.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="conditionValue" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>Identifies a Condition Descriptor that defines the measurable content that applies to a Condition. A Condition Value can be numeric, textual or an indicator (Yes, No). Numeric Condition Values can be qualified by a Unit Of Measure.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="code" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>This can be used for any Condition codes.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="hasConditionContext" type="crfpTO:ConditionContext_TO"/>
          <xsd:element minOccurs="0" name="purposeType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Distinguishes between Conditions according to the business activity they support or assist in accomplishing. Values within this Scheme are not mutually exclusive. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType abstract="true" name="BusinessModelObject_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies the highest class of objects in the hierarchy of the Financial Services Business Object Model representing a thing or a concept that is meaningful to the modeled Organization. Business Model Objects are superclasses of many objects that have business significance to business people and are used to provide common behavior across many object definitions. Examples of Business Model Object subclasses are Accounting Unit, Arrangement, Channel, Event, Product etc.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="universalUniqueIdentifier" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>Unique identifier for the Business Model Object</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="alternativeIdentifier" type="pdt:ObjectReference"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="isClassifiedBy" type="crfpTO:ClassificationValue_TO"/>
          <xsd:element minOccurs="0" name="objectType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The dynamic type for an instance of an object. E.g. for a DepositArrangement, this might specify FixedTermDepositArrangement to qualify what attributes are meaningful.Used to dynamically type an object as an instance of the specified type.Where an object has been created as a Testing/Training or Production object (e.g operationalNature), then the objectType Reference will be replaced by ObjectType, which includes an additional operationalNature element to reflect this where meaningful (e.g. "DepositArrangementType", "FixedTermDeposit", "Training"). The default value if a Reference is used rather than ObjectType, should be "Production"</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasConditions" type="crfpTO:Condition_TO">
            <xsd:annotation>
              <xsd:documentation>Identifies the Conditions to which the Business Model Objects refers</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="description" type="pdt:String"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Registration_TO">
    <xsd:annotation>
      <xsd:documentation>A formal granting, by an authorized body, of rights, privileges, favors, statuses, or qualifications. Registrations are important from the perspective of being a qualified source of information. Note that a Registration represents the actual granting, not the Document that represents those rights. that document is a Registration Document.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="isIssuedIn" type="crfpTO:GeographicArea_TO"/>
          <xsd:element minOccurs="0" name="lifeCycleStatus" type="pdt:LifecycleStatus">
            <xsd:annotation>
              <xsd:documentation>Life cycle status of the Registration</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="placeOfIssue" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>Place of the registration</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Customer_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party Role played by an Involved Party that is considered to be receiving services or products from the modeled organization or one of its Organization Units, or who is a potential recipient of such services or products.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedPartyRole_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="kycAssessmentChannel" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Specifies which channel carried out the Know Your Customer (KYC) assessment for the given customer. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedPartyRole_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular role played by a Role Player in a specific context. This role can specify additional information specific to the context, such as a mailing address for an account holder. The role can be identified independently of the context if the details are unavailable or irrelevant.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:RolePlayer_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="hasForContext" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>The identification of a Business Model Object as the context of an Involved Party Role</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="roleType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="lifecycleStatus" type="pdt:LifecycleStatus"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="ContactPreference_TO">
    <xsd:annotation>
      <xsd:documentation>The characteristics related to the way a Role Player wants to be contacted. This includes the contact points, the language, medium, name and timing preferences, the preferred contacting Individual as well as restrictions on the contact frequency. It also defines the usage such as business or private and the purpose, such as billing or mailing. </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="contactPoint" type="crfpTO:ContactPoint_TO">
            <xsd:annotation>
              <xsd:documentation>One or more points of contact for the Role Player under this Contact Preference</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="coveredArrangements" type="pdt:ObjectReference">
            <xsd:annotation>
              <xsd:documentation>Returns the Arrangements that are covered by this Contact Preference </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="correspondenceDestinationPreference" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>In relation to Arrangements held by the RolePlayer, the destination preference for correspondence on that Arrangement. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType abstract="true" name="RolePlayer_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies an Involved Party or a role played by an Involved Party within the context of the modeled organization.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BusinessModelObject_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="firstContactDate" type="pdt:String"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="isPlayingRole" type="crfpTO:InvolvedPartyRole_TO"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="isRegisteredIn" type="crfpTO:PartyRegistration_TO"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasForContactPreference" type="crfpTO:ContactPreference_TO"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="PartyRegistration_TO">
    <xsd:annotation>
      <xsd:documentation>An official recognition related to a Role Player. A Party Registration may be backed up by a Documentation Item</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:Registration_TO">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="registersParty" type="crfpTO:RolePlayer_TO">
            <xsd:annotation>
              <xsd:documentation>Identifies the Involved Partys that are the subjects of a Party Registration.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="NationalRegistration_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Party Registration that certifies an Involved Party as belonging to or governed by a national governmental entity. For example, social security registration, taxpayer identification, passport, citizenship identity card are forms of National Registration.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:PartyRegistration_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="countryCode" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="hasPrimaryResidence" type="pdt:Boolean"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="IndividualName_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a name structure used to specify a particular Individual or an Involved Party Role played by an Individual. </xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedPartyName_TO">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="middleNames" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The additional names given to an Individual, usually at birth, and which appear sequentially between the first name and last name.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="prefixTitle" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The honorifics or titles that precede the name when addressing an Individual in polite, somewhat formal circumstances.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="suffixTitle" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The titles, qualifications, or positions that follow the &lt;Individual&gt;'s name when addressing her formally or professionally, usually when writing.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="firstName" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The Individual's name normally preceding the last name and typically used to refer to the person in informal circumstances. For Example: John, Mary</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="lastName" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The part of a Individual's name arising from family identifications. e.g. Murphy.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedPartyName_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a name associated with an Involved Party. Multiple names are possible both concurrently and over time, varying by the use of the name such as the birth name or marriage name.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="nameText" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>Name text</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="description" type="pdt:Text"/>
          <xsd:element minOccurs="0" name="startDate" type="pdt:Date"/>
          <xsd:element minOccurs="0" name="endDate" type="pdt:Date"/>
          <xsd:element minOccurs="0" name="aliasType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="usage" type="pdt:Reference"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Organization_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party that is a group of Individuals bound by a common purpose. This includes commercial Organizations such as limited companies, publicly quoted multinationals, subsidiaries, etc. Organizations include Financial Organizations that provides products and services related to the financial services sector of the economy. Examples of such products and services include accepting deposits, making of loans, exchanging foreign currency, providing bill finance, handling foreign trade, managing investments and financing corporations. These financial organizations include the various types of banks (e.g.: retail banks, merchant banks, accepting houses, discount houses, foreign banks), building societies, pension funds, unit trusts, investment trusts and insurance companies. Financial organizations are either recognized as such by law or are regulated by a self regulating organization.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedParty_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="incorporationDate" type="pdt:Date">
            <xsd:annotation>
              <xsd:documentation>Identifies the date of the Incorporation of the Organization </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="isIncorporatedIn" type="crfpTO:GeographicArea_TO"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasTradingAddress" type="crfpTO:PostalAddress_TO">
            <xsd:annotation>
              <xsd:documentation>Attribute of the relationship between an Organization and a PostalAddress where the address is registered as a trading address for the Organization. Creation Date: 06/04/2018 Last Change Modeler: Julie Williamson Initiative: Party MDM</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="organizationClassificationType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="tradeStartMonth" type="pdt:Number">
            <xsd:annotation>
              <xsd:documentation>Month the Organization started trading.  Facilitates the requirement to break the trading start date into separate Month and Year elements.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="tradeStartYear" type="pdt:Number">
            <xsd:annotation>
              <xsd:documentation>Year the Organization started trading.  Facilitates the requirement to break the trading start date into separate Month and Year elements.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="fiscalYearEnd" type="pdt:Number"/>
          <xsd:element minOccurs="0" name="areaOfOperation" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="hasInternationalTrade" type="pdt:Reference"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="OrganizationUnit_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party that is a component or subdivision of an Organization established for the purpose of performing discrete functional responsibilities. This typically represents the Organizational structure of the modeled Organization including sections, departments, district offices, projects, and employment positions.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedParty_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="parentOrganization" type="crfpTO:Organization_TO">
            <xsd:annotation>
              <xsd:documentation>Returns the parent Organization for given Organization Unit. </xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedPartyAssociation_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies additional details about the association of one Involved Party to another Involved Party, for example, the delegated duty.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="associationStart" type="pdt:DateTime"/>
          <xsd:element minOccurs="0" name="associatedInvolvedParty" type="crfpTO:InvolvedParty_TO"/>
          <xsd:element minOccurs="0" name="associationEnd" type="pdt:DateTime"/>
          <xsd:element minOccurs="0" name="associationType" type="pdt:Reference"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="EducationCourse_TO">
    <xsd:complexContent>
      <xsd:extension base="crfpTO:BaseTransferObject">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="startDate" type="pdt:Date"/>
          <xsd:element minOccurs="0" name="endDate" type="pdt:Date"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="Individual_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Involved Party that is a natural person who is of interest to the modeled organization.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:InvolvedParty_TO">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="birthDate" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The birth date of the Individual</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="gender" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The Individual's sex or gender.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="maritalStatus" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="deathDate" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The date of the Individual's death. IBM Unique ID: IDM09020</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="occupation" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="birthPlace" type="pdt:String"/>
          <xsd:element minOccurs="0" name="hasBirthCountry" type="pdt:Reference"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasCitizenships" type="crfpTO:NationalRegistration_TO"/>
          <xsd:element minOccurs="0" name="additionalCitizenships" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>Identifies whether the &lt;Individual&gt; is a citizen of multiple countries and that the number of countries exceeds that in which RBS records the details. Note: In the current Core provider implementation, this indicator represents the situation where there are more than 4 countries of citizenship</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="primaryNationalityRegistration" type="crfpTO:NationalRegistration_TO"/>
          <xsd:element minOccurs="0" name="isStaff" type="pdt:String"/>
          <xsd:element minOccurs="0" name="employmentStatus" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="isHighNetWorth" type="pdt:String"/>
          <xsd:element minOccurs="0" name="specialCreditIndicatorType" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="mainSourceOfWealth" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="mainSourceOfIncome" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="consentToDataUsage" type="pdt:String"/>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="records" type="crfpTO:EducationCourse_TO"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="InvolvedParty_TO">
    <xsd:annotation>
      <xsd:documentation>Identifies a particular type of Role Player that is any participant that may have contact with, or that is of interest to the modeled organization, and about which the Financial Institution wishes to maintain information. This includes the modeled organization itself.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="crfpTO:RolePlayer_TO">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasForName" type="crfpTO:InvolvedPartyName_TO">
            <xsd:annotation>
              <xsd:documentation>name of the party</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="isSensitive" type="pdt:String"/>
          <xsd:element minOccurs="0" name="hasLegalAddress" type="crfpTO:PostalAddress_TO"/>
          <xsd:element minOccurs="0" name="hasPartyType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>The PartyType of the Involved Party</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasInvolvedPartyAssociation" type="crfpTO:InvolvedPartyAssociation_TO"/>
          <xsd:element minOccurs="0" name="hasRiskCountry" type="pdt:Reference"/>
          <xsd:element minOccurs="0" name="residesAt" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Specifies the Country the Involved Party resides at, for example John Doe resides in Canada.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element maxOccurs="unbounded" minOccurs="0" name="hasTaxRegistrations" type="crfpTO:NationalRegistration_TO"/>
          <xsd:element minOccurs="0" name="isPoliticallyExposed" type="pdt:String"/>
          <xsd:element minOccurs="0" name="isPrivateBankParty" type="pdt:String"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
</xsd:schema>




--------------------------------------------------

PrimitiveDatatypes.xsd

<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" version="RBS_20180711_Baseline" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/">
  <xsd:simpleType name="String">
    <xsd:annotation>
      <xsd:documentation>A string of characters (optionally containing blanks) for which a maximum length can be specified.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string"/>
  </xsd:simpleType>
  <xsd:complexType name="AddressComponent">
    <xsd:annotation>
      <xsd:documentation>An individual component of a postal address e.g. City, Zip Code. Inherits from Reference, which specifies type (City, Address Line 1 , PostCode ...)
</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:Reference">
        <xsd:sequence>
          <xsd:element maxOccurs="unbounded" name="address" type="pdt:String">
            <xsd:annotation>
              <xsd:documentation>The address content populating the specified PostalAddressComponentType</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:simpleType name="Time">
    <xsd:annotation>
      <xsd:documentation>An indication of a particular time in a day expressed with a maximum precision of one millisecond.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:time"/>
  </xsd:simpleType>
  <xsd:simpleType name="Text">
    <xsd:annotation>
      <xsd:documentation>A string of characters (optionally containing blanks) for which a maximum length cannot realistically be fixed.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string"/>
  </xsd:simpleType>
  <xsd:simpleType name="Number">
    <xsd:annotation>
      <xsd:documentation>A numeric value capable of holding a real number, not capable of holding a fractional or decimal value.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:integer"/>
  </xsd:simpleType>
  <xsd:simpleType name="ReturnCode">
    <xsd:annotation>
      <xsd:documentation>Identifies an opaque result handle defined to be zero for a successful return from a function and nonzero if error or status information is returned.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:integer"/>
  </xsd:simpleType>
  <xsd:simpleType name="Boolean">
    <xsd:annotation>
      <xsd:documentation>Boolean indicates a logical TRUE or FALSE condition.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:boolean"/>
  </xsd:simpleType>
  <xsd:complexType name="CurrencyAmount">
    <xsd:annotation>
      <xsd:documentation>A monetary amount including the Currency Type. Inherits from Amount, where the KeyValuePair identifies the Unit of Measure ClassificationScheme / Value for CurrencyType / Currency.  E.g. ISO4217 / GBP
</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:Amount">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="numberOfDecimalPlaces" type="pdt:Number"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:simpleType name="TimePeriod">
    <xsd:annotation>
      <xsd:documentation>A duration of time expressed in years, months, days, hours, minutes, and seconds.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:duration"/>
  </xsd:simpleType>
  <xsd:simpleType name="Percentage">
    <xsd:annotation>
      <xsd:documentation>A ratio, usually expressed as a number of units in 100. Strictly speaking a value outside of the range 0 to 100 is invalid, but these values are common.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:decimal"/>
  </xsd:simpleType>
  <xsd:simpleType name="Date">
    <xsd:annotation>
      <xsd:documentation>An indication of a particular day in the Gregorian calendar.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:date"/>
  </xsd:simpleType>
  <xsd:simpleType name="DateTime">
    <xsd:annotation>
      <xsd:documentation>An indication of a particular date and time expressed with a precision of one millisecond.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:dateTime"/>
  </xsd:simpleType>
  <xsd:simpleType name="Decimal">
    <xsd:annotation>
      <xsd:documentation>A numeric value that is not restricted to integer values and has a decimal point denoting fractional units.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:decimal"/>
  </xsd:simpleType>
  <xsd:simpleType name="Base64">
    <xsd:restriction base="xsd:base64Binary"/>
  </xsd:simpleType>
  <xsd:simpleType name="Byte">
    <xsd:annotation>
      <xsd:documentation>An 8-bit integer that is not signed</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:byte"/>
  </xsd:simpleType>
  <xsd:simpleType name="Identifier">
    <xsd:annotation>
      <xsd:documentation>A numeric value capable of holding a real number that uniquely identifies an instance.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:unsignedInt"/>
  </xsd:simpleType>
  <xsd:complexType name="Property">
    <xsd:annotation>
      <xsd:documentation>Represents key-value pair that allows for attachment of additional attributes to request header (and potentially also on other business objects (dynamic properties/hash table concept).</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:PropertyVariant">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="name" type="xsd:string">
            <xsd:annotation>
              <xsd:documentation>The name of a PropertyVariant.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="PropertyStructure">
    <xsd:sequence>
      <xsd:element maxOccurs="unbounded" name="properties" type="pdt:Property"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="NAPParameters">
    <xsd:annotation>
      <xsd:documentation>NAP Specific request parameters. Used by ATP operations establishFundsAvailability and establishFundsReservation. Complex Type made to consolidate unmodelled NAP elements in SDM
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="transactionFundsCode" type="pdt:Reference"/>
      <xsd:element name="transactionFundsCodeQualifier" type="pdt:Reference"/>
      <xsd:element name="eventType" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ObjectReference">
    <xsd:annotation>
      <xsd:documentation>Identifier of the corresponding business object. Multiple ObjectReferences may identify a single object. ObjectReferences contain a context that describes the type and governance of the identifier instance.
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="identifier" type="pdt:String"/>
      <xsd:element name="context" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="description" type="pdt:Text"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="extendedProperties" type="pdt:PropertyVariant">
        <xsd:annotation>
          <xsd:documentation>Generic element to facilitate technical extensions to the Business Model. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Binary">
    <xsd:annotation>
      <xsd:documentation>A finite sequence of bytes. The definition consists of two logical elements: binary data and binary data length. Inherits from KeyValuePair, which specifies a ClassificationScheme and Value identifying theContentType.  E.g. a Scheme of MimeTypes and a Value of aiff
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="binaryData" type="xsd:byte">
        <xsd:annotation>
          <xsd:documentation>The data contained in the type</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="length" type="xsd:integer">
        <xsd:annotation>
          <xsd:documentation>The length of data contained in this type
</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="binaryType" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="LifecycleStatus">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="status" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="effectiveDate" type="pdt:DateTime"/>
      <xsd:element minOccurs="0" name="endDate" type="pdt:DateTime"/>
      <xsd:element minOccurs="0" name="priorStatus" type="pdt:LifecycleStatus"/>
      <xsd:element minOccurs="0" name="plannedStatus" type="pdt:LifecycleStatus"/>
      <xsd:element minOccurs="0" name="statusReason" type="pdt:Reference">
        <xsd:annotation>
          <xsd:documentation>Identifies the different types of reasons that are the rationale for a LifecycleStatus current status.
</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="PropertyVariant">
    <xsd:annotation>
      <xsd:documentation>Identifies a generic structure that is capable of holding multiple types of data, which is stored in an independent format within the type.
</xsd:documentation>
    </xsd:annotation>
    <xsd:choice>
      <xsd:element minOccurs="0" name="amount" type="pdt:Amount"/>
      <xsd:element minOccurs="0" name="structure" type="pdt:PropertyStructure"/>
      <xsd:element minOccurs="0" name="binary" type="pdt:Binary"/>
      <xsd:element minOccurs="0" name="_boolean" type="pdt:Boolean"/>
      <xsd:element minOccurs="0" name="_byte" type="pdt:Byte"/>
      <xsd:element minOccurs="0" name="currencyAmount" type="pdt:CurrencyAmount"/>
      <xsd:element minOccurs="0" name="date" type="pdt:Date"/>
      <xsd:element minOccurs="0" name="dateTime" type="pdt:DateTime"/>
      <xsd:element minOccurs="0" name="decimal" type="pdt:Decimal"/>
      <xsd:element minOccurs="0" name="identifier" type="pdt:Identifier"/>
      <xsd:element minOccurs="0" name="number" type="pdt:Number"/>
      <xsd:element minOccurs="0" name="percentage" type="pdt:Percentage"/>
      <xsd:element minOccurs="0" name="reference" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="string" type="pdt:String"/>
      <xsd:element minOccurs="0" name="time" type="pdt:Time"/>
      <xsd:element minOccurs="0" name="timePeriod" type="pdt:TimePeriod"/>
      <xsd:element minOccurs="0" name="base64" type="xsd:base64Binary"/>
      <xsd:element minOccurs="0" name="objectReference" type="pdt:ObjectReference"/>
    </xsd:choice>
  </xsd:complexType>
  <xsd:complexType name="fileLocation">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="fileLocation" type="pdt:String"/>
      <xsd:element minOccurs="0" name="fileAddressType" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="accountingTransactionParameter">
    <xsd:sequence>
      <xsd:element name="instructionIdentifer" type="pdt:ObjectReference"/>
      <xsd:element name="transactionIdentifer" type="pdt:ObjectReference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ObjectType">
    <xsd:complexContent>
      <xsd:extension base="pdt:Reference">
        <xsd:sequence>
          <xsd:element name="operationalNature" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Indicates whether the particular BMO instance is created for Production, Test or Training purposes.
</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="LanguageSpecificDescriptor">
    <xsd:annotation>
      <xsd:documentation>Language specific name and optional description for an Object.  The inherited KeyValuePair identifies the language meta-data managed as ReferenceData</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="name" type="xsd:string"/>
      <xsd:element minOccurs="0" name="description" type="xsd:string"/>
      <xsd:element name="language" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Amount">
    <xsd:annotation>
      <xsd:documentation>A numeric count including units, such as litres, inches, or kilometres per litre. An example would be 150 km/h.
Includes a ReferenceIdentifier theUnit, which identifies a specific ClassificationScheme and Value representing theUnit. E.g. a Scheme for Volumetric Units of Measure and a Value of Liters
</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="amount" type="xsd:decimal">
        <xsd:annotation>
          <xsd:documentation>The amount being measured</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="unitOfMeasure" type="pdt:Reference"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="BalanceType">
    <xsd:annotation>
      <xsd:documentation>BalanceDerivationType combined with PointBalanceType as the basis for retrieval of AccountingUnit by Type operation.</xsd:documentation>
    </xsd:annotation>
    <xsd:complexContent>
      <xsd:extension base="pdt:Reference">
        <xsd:sequence>
          <xsd:element minOccurs="0" name="pointBalanceType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>Distinguishes between Point Balances according to whether they are associated with the beginning, middle or end of a specified interval of time.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
          <xsd:element minOccurs="0" name="accountingEffectType" type="pdt:Reference">
            <xsd:annotation>
              <xsd:documentation>A Classification Scheme that distinguishes between Posting Entries based on whether they increase or decrease the balance of a particular type of Accounting Unit.</xsd:documentation>
            </xsd:annotation>
          </xsd:element>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:complexType name="TransactionHistoryFilter">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="transactionType" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="postingStatus" type="pdt:Reference"/>
      <xsd:element minOccurs="0" name="startDate" type="pdt:Date"/>
      <xsd:element minOccurs="0" name="endDate" type="pdt:Date"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Reference">
    <xsd:annotation>
      <xsd:documentation>Used extensively for representing the name of a ClassificationScheme.name and ReferenceClassification.code in a managed ReferenceData repository. The managed meta-data referenced by such a Reference attribute instance, is retrievable using CRUD operations on ClassificationScheme and Value </xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="schemeName" type="xsd:string">
        <xsd:annotation>
          <xsd:documentation>Holds the scheme of the ClassificationScheme / Value pair.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="codeValue" type="xsd:string">
        <xsd:annotation>
          <xsd:documentation>Holds the value of a  ClassificationScheme / Value pair.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="description" type="pdt:Text"/>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>


----------------------------------------

ServiceDefinitions.xsd

<?xml version="1.0" encoding="UTF-8"?><xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://com/rbsg/soa/Services/Definitions/V03/" version="RBS_20180717_Baseline" xmlns:pdt="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" xmlns:sdef="http://com/rbsg/soa/Services/Definitions/V03/">
  <xsd:import namespace="http://com/rbsg/soa/DataTypes/PrimitiveDataTypes/V03/" schemaLocation="PrimitiveDatatypes.xsd"/>
  <xsd:complexType name="ResponseCursor">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="resultSetID" type="pdt:PropertyVariant"/>
      <xsd:element minOccurs="0" name="countReturned" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Number of responses returned</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="maxCount" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Total number of results found</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="SMMValue" type="pdt:Property">
        <xsd:annotation>
          <xsd:documentation>Start reference in result set to return from.  This may be a composite set of properties.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="SMMIndicator" type="pdt:Boolean">
        <xsd:annotation>
          <xsd:documentation>Indicator of more information available</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:simpleType name="NotificationCategory">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between notification according to the status of processing reported.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Error">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting an error during the processing. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Info">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting an information about what happened during the processing.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Warning">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting a warning about what happened during the processing.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Abort">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting that the processing had to be aborted. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Success">
        <xsd:annotation>
          <xsd:documentation>Identifies a notification reporting that the processing had benn succesfully completed.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandRequestcmd">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between request commands according to their nature.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Request">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a request.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Notification">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a notification (one way message). </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Acknowledge"/>
      <xsd:enumeration value="Heartbeat">
        <xsd:annotation>
          <xsd:documentation>To enable service platform heartbeat service</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="ESPHeartbeat">
        <xsd:annotation>
          <xsd:documentation>To enable service platform heartbeat service</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandExceptioncmdStatus">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between exception messages according to the status of processing reported. </xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="NotExecuted">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had not been executed at all.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Failed">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had failed to complete. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandRequestcmdMode">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between request commands according to the response expectations. </xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="OnlyRespondInError">
        <xsd:annotation>
          <xsd:documentation>Identifies a (request) message to expect a response only in the case of error. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="NeverRespond">
        <xsd:annotation>
          <xsd:documentation>Identifies a (request) message not to expect a response at all. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="AlwaysRespond">
        <xsd:annotation>
          <xsd:documentation>Identifies a (request) message to always expect a response. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:simpleType name="CommandResponsecmd">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between response commands according to their nature. </xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Response">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a response. </xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Notification">
        <xsd:annotation>
          <xsd:documentation>Identifies a nature of a message to be a notification (one way message).</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:complexType name="ProcessingIdentifier">
    <xsd:annotation>
      <xsd:documentation>Represents a system generated (major) transaction identifier assigned to this processing.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="systemId" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Identifies the system initiating the transaction. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="transactionId" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Identifies the transaction.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:simpleType name="CommandResponsecmdStatus">
    <xsd:annotation>
      <xsd:documentation>Distinguishes between response messages according to the status of processing reported.</xsd:documentation>
    </xsd:annotation>
    <xsd:restriction base="xsd:string">
      <xsd:enumeration value="Succeeded">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had been succesfully completed.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="PartiallySucceeded">
        <xsd:annotation>
          <xsd:documentation>Identifies a response message reporting that the processing had been partially succesfully completed.</xsd:documentation>
        </xsd:annotation>
      </xsd:enumeration>
      <xsd:enumeration value="Acknowledged"/>
    </xsd:restriction>
  </xsd:simpleType>
  <xsd:complexType name="RequestCursor">
    <xsd:sequence>
      <xsd:element minOccurs="0" name="resultSetID" type="pdt:PropertyVariant"/>
      <xsd:element minOccurs="0" name="countRequested" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Maximum number of responses to be returned</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="maxCount" type="pdt:Number">
        <xsd:annotation>
          <xsd:documentation>Default maximum number to return if countRequested not specified</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="SMMValue" type="pdt:Property">
        <xsd:annotation>
          <xsd:documentation>Start reference in result set to return from.  This may be a composite set of properties.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="SMMIndicator" type="pdt:Boolean">
        <xsd:annotation>
          <xsd:documentation>Indicator of more information available</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="ResponseHeader">
    <xsd:annotation>
      <xsd:documentation>Represent the header information returned with each response message.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="responseId" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Represents the integration system (e.g. DataPower) generated (major) transaction identifier, which identify the system sending the message and system generated ID (number) for the message. Used mostly only for logging/tracking purposes.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="operatingBrand" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the operating brand (inside RBS) that has sent this command. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="refRequestIds" type="sdef:ProcessingIdentifier"/>
      <xsd:element minOccurs="0" name="cmdType" type="sdef:CommandResponsecmd">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the type of the command (can be Response or Notification the case of RequestHeader).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdStatus" type="sdef:CommandResponsecmdStatus">
        <xsd:annotation>
          <xsd:documentation>Specifies the status of the request processing on the provider side (success/failure/unknown).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="cmdNotifications" type="sdef:CommandNotification">
        <xsd:annotation>
          <xsd:documentation>Contains the list of Commands (if any) optionally returned with the response (informing about potential business errors that occurred during the request processing).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="Exception">
    <xsd:annotation>
      <xsd:documentation>Represent the Service/Message Error object that can be returned as an optional service/message invocation response.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="responseId" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Represents the integration system (e.g. DataPower) generated (major) transaction identifier, which identify the system sending the message and system generated ID (number) for the message. Used mostly only for logging/tracking purposes.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="refRequestIds" type="sdef:ProcessingIdentifier"/>
      <xsd:element minOccurs="0" name="operatingBrand" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the operating brand (inside RBS) that has sent this command. </xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="serviceName" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Holds the name of the service to whose operation this SOAFault object is response to.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element name="operationName" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Holds the name of the service operation to which this SOAFault object is response to.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdStatus" type="sdef:CommandExceptioncmdStatus"/>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="cmdNotifications" type="sdef:CommandNotification"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="CommandNotification">
    <xsd:annotation>
      <xsd:documentation>Specifies the CommandNotification's category (Error/Warning/Info/...).</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="returnCode" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the ESB CommandNotification's error code.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="category" type="sdef:NotificationCategory">
        <xsd:annotation>
          <xsd:documentation>Represents a system notification that can be received as part of a CommandNotification. This is the representation of a notification triggered by a single system in reaction for receiving the service request.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="description" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Holds the ESB CommandNotification's textual description.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="timestamp" type="pdt:DateTime">
        <xsd:annotation>
          <xsd:documentation>Holds the ESB CommandNotification's timestamp - when it was created.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="systemNotifications" type="sdef:SystemNotification">
        <xsd:annotation>
          <xsd:documentation>Contains the (optional) list of underlying SystemNotifications that resulted in/are the reason for in this CommandNotification</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="SystemNotification">
    <xsd:annotation>
      <xsd:documentation>Represents a system notification that can be received as part of a CommandNotification. This is the representation of a notification triggered by a single system in reaction for receiving the service request.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element minOccurs="0" name="returnCode" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the SystemNotification's error code.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="category" type="sdef:NotificationCategory">
        <xsd:annotation>
          <xsd:documentation>Specifies the SystemNotification's category (Error/Warning/Info/...).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="description" type="pdt:Text">
        <xsd:annotation>
          <xsd:documentation>Specifies the text of the SystemMessage.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="processingId" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Represents the 'transaction identifier' assigned to the processing by a provider integration system.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:complexType name="RequestHeader">
    <xsd:annotation>
      <xsd:documentation>Represent the header information send with each request message.</xsd:documentation>
    </xsd:annotation>
    <xsd:sequence>
      <xsd:element name="operatingBrand" type="pdt:String">
        <xsd:annotation>
          <xsd:documentation>Specifies the operating brand (inside RBS) that has sent this command.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element maxOccurs="unbounded" minOccurs="0" name="requestIds" type="sdef:ProcessingIdentifier">
        <xsd:annotation>
          <xsd:documentation>Specifies the processing 'transaction Ids', assigned to the processing by individual service invocation layers - used mostly for logging/tracking.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdType" type="sdef:CommandRequestcmd">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the type of the command (can be Request or Notification the case of RequestHeader).</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="cmdMode" type="sdef:CommandRequestcmdMode">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the request is expecting a response to be sent back (under which circumstance a response is expected)</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
      <xsd:element minOccurs="0" name="echoBack" type="xsd:boolean">
        <xsd:annotation>
          <xsd:documentation>Specifies whether the response should echo back the request's data.</xsd:documentation>
        </xsd:annotation>
      </xsd:element>
    </xsd:sequence>
  </xsd:complexType>
</xsd:schema>





