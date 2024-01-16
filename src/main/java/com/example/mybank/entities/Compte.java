package com.example.mybank.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

@Data
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="TYPE_CPTE", discriminatorType = DiscriminatorType.STRING, length = 2)

public abstract class  Compte implements Serializable {
    @Id
    private String codeCompte;
    private Date dateCreation;
    private double solde;
    @ManyToOne
    @JoinColumn(name="CODE_CLI")
    private Client client;
    @OneToMany(mappedBy = "compte", fetch= FetchType.LAZY)
    private Collection<Transactions> transactions;
}
