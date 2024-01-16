package com.example.mybank.entities;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Data;

import java.util.Date;

@Data
@Entity
@DiscriminatorValue("CE")
public class CompteEpargne extends Compte{
    private double taux;


    public CompteEpargne(String c1, Date date, double montant, Client client, double taux) {
    }
}
