CustomerData customerData;

Optional<CustomerInfoAudit> dbResult = repository.findByAccountNo(accountNumber);
if (dbResult.isPresent()) {
    customerData = dbResult.get().toCustomerData();
} else {
    CustomerNameMapping matched = CustomerNameMapping.fromIdentifier(accountNumber);
    if (matched != null) {
        customerData = matched.toCustomerData();
    } else {
        throw new RuntimeException("Customer not found");
    }
}

updateName(doc, xpath, customerData);



------
package com.rbs.bdd.domain.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "customer_info_audit")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustomerInfoAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_no", nullable = false, unique = true)
    private String accountNo;

    @Column(name = "prefix_type")
    private String prefixType;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "account_type")
    private String accountType;

    // Add timestamps if needed
    // @Column(name = "created_at")
    // private LocalDateTime createdAt;
}



------
package com.rbs.bdd.application.port.out;

import com.rbs.bdd.domain.entity.CustomerInfoAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomerInfoAuditRepository extends JpaRepository<CustomerInfoAudit, Long> {
    
    Optional<CustomerInfoAudit> findByAccountNo(String accountNo);
}
