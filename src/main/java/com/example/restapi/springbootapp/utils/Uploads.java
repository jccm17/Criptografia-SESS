package com.example.restapi.springbootapp.utils;

import java.io.File;
import java.util.Objects;

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

    public void eliminarTodo(String folder) {
        File directory = new File(folder);
        for (File file : Objects.requireNonNull(directory.listFiles())) {
            if (!file.isDirectory()) {
                file.delete();
                System.out.println("file delete success");
            }
        }
    }
}