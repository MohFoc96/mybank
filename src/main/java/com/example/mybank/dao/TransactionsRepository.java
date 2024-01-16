package com.example.mybank.dao;

import com.example.mybank.entities.Transactions;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TransactionsRepository extends JpaRepository<Transactions,Long> {
    @Query("select t from Transactions t where t.compte.codeCompte=:x order by o.dateOperation desc")
    public Page<Transactions> listTransanctions(@Param("x") String code , Pageable pageable);
}
