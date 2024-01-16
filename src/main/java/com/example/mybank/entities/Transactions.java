package com.example.mybank.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="TYPE_TRA", discriminatorType = DiscriminatorType.STRING, length = 2)

public abstract class Transactions implements Serializable {
    @Id @GeneratedValue
    private Long numero;
    private Date dateTransaction;
    private double montant;
    @ManyToOne
    @JoinColumn(name="CODE_CPTE")
    private Compte compte;

}
