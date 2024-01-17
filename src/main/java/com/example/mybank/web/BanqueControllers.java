package com.example.mybank.web;

import com.example.mybank.entities.*;
import com.example.mybank.service.IBanqueService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class BanqueControllers {

    @Autowired
    private IBanqueService banqueService;

    @PostMapping("/createCompte")
    @ResponseStatus(HttpStatus.CREATED)
    public Client createClient(@RequestBody Client client){
        return banqueService.creationClient(client.getNom(), client.getEmail());
    }

    @PostMapping("/createCompteCourant")
    @ResponseStatus(HttpStatus.CREATED)
    public Compte createCompteCourant(@RequestBody CompteCourant compte){
        return banqueService.creationCompteCourant(compte.getCodeCompte(), compte.getSolde(),compte.getClient(),compte.getDecouvert());
    }

    @PostMapping("/createCompteEpargne")
    @ResponseStatus(HttpStatus.CREATED)
    public Compte createCompteEpargne(@RequestBody CompteEpargne compte){
        return banqueService.creationCompteEpargne(compte.getCodeCompte(), compte.getSolde(),compte.getClient(),compte.getTaux());
    }

    @PostMapping("/createDepot")
    @ResponseStatus(HttpStatus.CREATED)
    public Transactions createCompte(@RequestBody Compte compte, @RequestParam double montant){
        return banqueService.creationDepot(montant,compte);
    }

    @PostMapping("/createRetrait")
    @ResponseStatus(HttpStatus.CREATED)
    public Transactions createRetrait(@RequestBody Compte compte, @RequestParam double montant){
        return banqueService.creationRetrait(montant,compte);
    }
    @PutMapping("/updateClient")
    public Client updateNomClient(@RequestBody Client client) {
        return  banqueService.updateNomClient(client.getNom(), client.getCode());
    }

    @DeleteMapping("/delete")
    public void deleteClient(@RequestBody Client client) {
        banqueService.deleteClient(client);
    }

    @GetMapping("/consulterCompte")
    public Compte consulter (@RequestBody Compte compte){
        return banqueService.consulterCompte(compte.getCodeCompte());
    }

    @PostMapping("/virement")
    public void virement(@RequestBody Compte compte1, @RequestBody Compte compte2, @RequestParam double montant) {
        banqueService.virement(compte1.getCodeCompte(), compte2.getCodeCompte(), montant);
    }
    }
