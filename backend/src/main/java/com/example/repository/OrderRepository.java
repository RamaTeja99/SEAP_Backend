package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.entity.PaymentOrder;
import java.util.Optional;

public interface OrderRepository extends JpaRepository<PaymentOrder, Long> {
    Optional<PaymentOrder> findByRazorpayOrderId(String razorpayOrderId);
}
