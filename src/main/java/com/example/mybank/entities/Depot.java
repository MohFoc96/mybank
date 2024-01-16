package com.example.mybank.entities;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Data;

import java.util.Date;

@Data
@Entity
@DiscriminatorValue("D")
public class Depot extends Transactions{
    public Depot(Date date, double montant, Compte compte) {
    }
}
