package com.example.mybank.service;

import com.example.mybank.entities.Client;
import com.example.mybank.entities.Compte;
import com.example.mybank.entities.Transactions;
import org.springframework.data.domain.Page;

import java.util.Date;
import java.util.Optional;

public interface IBanqueService {
    public Client creationClient(String nom , String email);
    public Compte creationCompteCourant(String C1, double montant,Client client,double dec);
    public Compte creationCompteEpargne(String C1, double montant,Client client,double taux);
    public Transactions creationDepot(double montant , Compte compte);
    public Transactions creationRetrait(double montant , Compte compte);
    public Client updateNomClient(String nom , Long Code);
    public void deleteClient(Client client);
    public Compte consulterCompte(String code);
    public void virement (String codeCpte1, String codeCpte2,double montant);
    public Page<Transactions> listTransactions(String codeCpte, int page,int size);


}
