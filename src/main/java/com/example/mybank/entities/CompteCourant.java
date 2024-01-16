package com.example.mybank.entities;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Data;

import java.util.Date;

@Data
@Entity
@DiscriminatorValue("CC")
public class CompteCourant extends Compte {

    private double decouvert;


    public CompteCourant(String c1, Date date, double montant, Client client, double dec) {
    }
}
