package com.example.restapi.springbootapp.dto;

import java.io.Serializable;

import org.springframework.web.multipart.MultipartFile;

import io.swagger.v3.oas.annotations.media.Schema;
/**
 *
 * @author Jccm.17
 */
public class Archivo implements Serializable{
 
    @Schema(description = "Metodo de cifrado ejm: BASE64, MD5, AES. ETC..", required = true)
    private String metodo;

    @Schema(description = "Archivo a descifrar", required = true)
    private MultipartFile archivo;

    public String getMetodo() {
        return metodo;
    }
    public void setMetodo(String metodo) {
        this.metodo = metodo;
    }
    public MultipartFile getArchivo() {
        return archivo;
    }
    public void setArchivo(MultipartFile archivo) {
        this.archivo = archivo;
    }

}
