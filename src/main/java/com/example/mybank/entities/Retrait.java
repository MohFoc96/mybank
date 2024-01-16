package com.example.mybank.entities;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Data;

import java.util.Date;

@Data
@Entity
@DiscriminatorValue("R")
public class Retrait extends Transactions{

    public Retrait(Date date, double montant, Compte compte) {
    }
}
