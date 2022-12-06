package com.example.restapi.springbootapp.utils;

import java.io.File;

/**
 *
 * @author Jccm.17
 */
public class Uploads {

    public void eliminar(String file) {

        File fichero = new File(file);
        if (fichero.delete())
            System.out.println("file delete success");
        else
            System.out.println("fail delete file");
    }

}