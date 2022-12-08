package com.example.restapi.springbootapp.dto;

import java.io.Serializable;

import io.swagger.v3.oas.annotations.media.Schema;

public class DatoNormal implements Serializable{
    
    private String textoNormal;

    @Schema(description = "Metodo de cifrado ejm: BASE64, MD5, AES, 3DES, IDEA, ETC..", required = true)
    private String metodo;

    public String getTextoNormal() {
        return textoNormal;
    }
    public void setTextoNormal(String textoNormal) {
        this.textoNormal = textoNormal;
    }
    public String getMetodo() {
        return metodo;
    }
    public void setMetodo(String metodo) {
        this.metodo = metodo;
    }

}
