package com.example.mybank.entities;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;
import java.util.Collection;
@Entity
@Data
public class Client  implements Serializable{
    @Id @GeneratedValue
    private Long code;
    private String nom;
    private String email;
    @OneToMany(mappedBy = "client", fetch= FetchType.LAZY)
    private Collection<Compte> comptes;

    public Client(String nom, String email) {
    }
}
