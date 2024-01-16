package com.example.mybank.service;

import com.example.mybank.dao.ClientRepository;
import com.example.mybank.dao.CompteRepository;
import com.example.mybank.dao.TransactionsRepository;
import com.example.mybank.entities.*;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
@Transactional
public class BanqueServices implements IBanqueService{
    @Autowired
    ClientRepository clientRepository;
    @Autowired
    TransactionsRepository transactionsRepository;
    @Autowired
    CompteRepository compteRepository;

    @Override
    public Client creationClient(String nom, String email) {

        Client client = clientRepository.save(new Client(nom,email));
        return client;
    }

    @Override
    public Compte creationCompteCourant(String C1, double montant,Client client,double dec) {
        Compte compte = compteRepository.save(new CompteCourant(C1,new Date(), montant,client,dec));
        return compte;
    }

    @Override
    public Compte creationCompteEpargne(String C1, double montant,Client client,double taux) {
        Compte compte = compteRepository.save(new CompteEpargne(C1,new Date(),montant,client,taux));
        return null;
    }

    @Override
    public Transactions creationDepot(double montant, Compte compte) {
        Transactions transactions = transactionsRepository.save(new Depot(new Date(),montant,compte));
        double newsolde = compte.getSolde() + montant;
        compte.setSolde(newsolde);
        compteRepository.save(compte);
        return transactions;
    }

    @Override
    public Transactions creationRetrait(double montant, Compte compte) {
        double facilities = 0;
        if (compte instanceof  CompteCourant)
            facilities = ((CompteCourant) compte).getDecouvert();
        if(compte.getSolde()+ facilities < 0)
            throw new RuntimeException("Solde Insuffisant");
        Transactions transactions = transactionsRepository.save(new Retrait(new Date(),montant,compte));
        double newsolde = compte.getSolde() - montant;
        compte.setSolde(newsolde);
        compteRepository.save(compte);
        return transactions;
    }

    @Override
    public Client updateNomClient(String nom, Long code) {

        Client client = clientRepository.getById(code);
        client.setNom(nom);
        clientRepository.save(client);

        return null;
    }

    @Override
    public void deleteClient(Client client) {
        clientRepository.delete(client);

    }

    @Override
    public Compte consulterCompte(String code) {
        Compte compte = compteRepository.getById(code);
        if (compte==null) throw new RuntimeException("Compte introuvable");
        return compte;
    }

    @Override
    public void virement(String codeCpte1, String codeCpte2, double montant) {
        creationDepot(montant,consulterCompte(codeCpte1) );
        creationRetrait(montant , consulterCompte(codeCpte2));

    }

    @Override
    public Page<Transactions> listTransactions(String codeCpte, int page, int size) {
        return transactionsRepository.listTransanctions(codeCpte, PageRequest.of(page,size));
    }
}
