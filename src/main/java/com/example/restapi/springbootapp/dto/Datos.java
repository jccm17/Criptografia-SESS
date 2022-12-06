package com.example.restapi.springbootapp.dto;

import java.io.Serializable;

import io.swagger.v3.oas.annotations.media.Schema;

public class Datos implements Serializable{

    private String textoCifrado;

    @Schema(description = "Metodo de descifrado ejm: BASE64, MD5, AES. ETC..", required = true)
    private String metodo;

    public String getTextoCifrado() {
        return textoCifrado;
    }

    public void setTextoCifrado(String textoCifrado) {
        this.textoCifrado = textoCifrado;
    }

    public String getMetodo() {
        return metodo;
    }

    public void setMetodo(String metodo) {
        this.metodo = metodo;
    }

}
