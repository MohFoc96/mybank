package com.example.mybank.dao;

import com.example.mybank.entities.Compte;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CompteRepository extends JpaRepository<Compte,String> {
}
