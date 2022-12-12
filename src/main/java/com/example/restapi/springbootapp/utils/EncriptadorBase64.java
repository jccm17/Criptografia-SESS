package com.example.restapi.springbootapp.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
/**
 *
 * @author Jccm.17
 */
public class EncriptadorBase64 {

    public void encodeFile(String inputFile, String outputFile)
            throws IOException {
        Path inPath = Paths.get(inputFile);
        Path outPath = Paths.get(outputFile);
        try (OutputStream out = Base64.getEncoder().wrap(Files.newOutputStream(outPath))) {
            Files.copy(inPath, out);
        }
    }

    public void decodeFile(String encodedfilecontent, String decodedfile)
            throws IOException {
        Path inPath = Paths.get(encodedfilecontent);
        Path outPath = Paths.get(decodedfile);
        try (InputStream in = Base64.getDecoder().wrap(Files.newInputStream(inPath))) {
            Files.copy(in, outPath);
        }
    }
}
