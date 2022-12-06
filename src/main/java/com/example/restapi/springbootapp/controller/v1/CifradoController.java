package com.example.restapi.springbootapp.controller.v1;

import com.example.restapi.springbootapp.dto.ArchivoNormal;
import com.example.restapi.springbootapp.dto.DatoNormal;
import com.example.restapi.springbootapp.dto.Datos;
import com.example.restapi.springbootapp.utils.EncriptadorAES;
import com.example.restapi.springbootapp.utils.EncriptadorMD5;
import com.example.restapi.springbootapp.utils.Uploads;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.servers.Server;

import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.validation.Valid;

@OpenAPIDefinition(servers = {@Server(url = "https://encriptacion-sess.herokuapp.com/"), @Server(url = "http://localhost:9090")}, info = @Info(title = "Encriptacion Spring Boot API", version = "v1", description = "A project using Spring Boot with Swagger-UI enabled", license = @License(name = "MIT License", url = "https://github.com/bchen04/springboot-swagger-rest-api/blob/master/LICENSE"), contact = @Contact(url = "https://www.jccm.xyz", name = "SESS")))
@RestController
@RequestMapping("v1/")
public class CifradoController {

    private final Path root = Paths.get("uploads");

    Uploads f = new Uploads();
    EncriptadorAES aes = new EncriptadorAES();
    EncriptadorMD5 md5 = new EncriptadorMD5();
    final String claveEncriptacion = "cifrado128AES25!";

    @Operation(summary = "Retorna Texto en cifrado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Operacion exitosa", content = @Content(schema = @Schema(type = "object"))) })
    @PostMapping(value = "encriptar", produces = { "application/json" })
    public ResponseEntity<?> encriptar(@Valid @RequestBody DatoNormal data) {
        Map<String, Object> response = new HashMap<>();
        String text = "";
        try {
            switch (data.getMetodo()) {
                case "BASE64":
                    response.put("textoCifrado", Base64.getEncoder().encodeToString(data.getTextoNormal().getBytes()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES":
                    response.put("textoCifrado", aes.encriptar(data.getTextoNormal(), claveEncriptacion));
                    response.put("metodo", data.getMetodo());
                    break;
                case "MD5":
                    response.put("textoCifrado", md5.encode(data.getTextoNormal()));
                    response.put("metodo", data.getMetodo());
                    break;
                default:
                    response.put("textoCifrado", text);
                    response.put("metodo", "No definido, desconocido");
                    break;
            }

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @Operation(summary = "Retorna Texto descifrado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Operacion exitosa", content = @Content(schema = @Schema(type = "object"))) })
    @PostMapping(value = "desencriptar", produces = { "application/json" })
    public ResponseEntity<?> desencriptar(@Valid @RequestBody Datos data) {
        Map<String, Object> response = new HashMap<>();
        String text = "";
        try {
            switch (data.getMetodo()) {
                case "BASE64":
                    byte[] decodedBytes = Base64.getUrlDecoder().decode(data.getTextoCifrado());
                    String decodedUrl = new String(decodedBytes);
                    response.put("textoDescifrado", decodedUrl);
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES":
                    response.put("textoDescifrado", aes.desencriptar(data.getTextoCifrado(), claveEncriptacion));
                    response.put("metodo", data.getMetodo());
                    break;
                case "MD5":
                    response.put("textoDescifrado", md5.decode(data.getTextoCifrado()));
                    response.put("metodo", data.getMetodo());
                    break;
                default:
                    response.put("textoCifrado", text);
                    response.put("metodo", "No definido, desconocido");
                    break;
            }

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @Operation(summary = "Retorna Archivo cifrado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Operacion exitosa", content = @Content(schema = @Schema(type = "object"))) })
    @PostMapping(value = "encriptar/archivo", consumes = "multipart/form-data")
    public ResponseEntity<?> encriptarArchivo(@ModelAttribute ArchivoNormal data) {
        Map<String, Object> response = new HashMap<>();
        String path = "";
        String text = "";
        try {
            String nameFile = UUID.randomUUID() + data.getArchivo().getOriginalFilename();
            Files.copy(data.getArchivo().getInputStream(), this.root.resolve(nameFile));
            path = "uploads/" + nameFile;

            switch (data.getMetodo()) {
                case "BASE64":
                    File file = new File(path);
                    byte[] fileContent = Files.readAllBytes(file.toPath());
                    response.put("archivoCifrado", Base64.getEncoder().encodeToString(fileContent));
                    response.put("metodo", data.getMetodo());
                    encodeFile(path, "test");
                    break;
                case "AES":
                    response.put("metodo", data.getMetodo());
                    break;
                case "HASH":
                    response.put("metodo", data.getMetodo());
                    break;
                default:
                    response.put("archivoCifrado", text);
                    response.put("metodo", "No definido, desconocido");
                    break;
            }

            f.eliminar("uploads/" + nameFile);
            response.put("archivoName", nameFile);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @Operation(summary = "Retorna Archivo descifrado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Operacion exitosa", content = @Content(schema = @Schema(type = "object"))) })
    @PostMapping(value = "desencriptar/archivo", consumes = "multipart/form-data")
    public ResponseEntity<?> desencriptarArchivo(@Valid @RequestBody Datos data) {
        Map<String, Object> response = new HashMap<>();
        String path = "";
        String text = "";
        try {
            switch (data.getMetodo()) {
                case "BASE64":
                    response.put("archivoCifrado", null);
                    response.put("metodo", data.getMetodo());
                    decodeFile(data.getTextoCifrado(), data.getTextoCifrado());
                    break;
                case "AES":
                    response.put("metodo", data.getMetodo());
                    break;
                case "HASH":
                    response.put("metodo", data.getMetodo());
                    break;
                default:
                    response.put("archivoCifrado", text);
                    response.put("metodo", "No definido, desconocido");
                    break;
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    private static void encodeFile(String inputFile, String outputFile)
            throws IOException {
        Path inPath = Paths.get(inputFile);
        Path outPath = Paths.get(outputFile);
        try (OutputStream out = Base64.getEncoder().wrap(Files.newOutputStream(outPath))) {
            Files.copy(inPath, out);
        }
    }

    private static void decodeFile(String encodedfilecontent, String decodedfile)
            throws IOException {
        Path inPath = Paths.get(encodedfilecontent);
        Path outPath = Paths.get(decodedfile);
        try (InputStream in = Base64.getDecoder().wrap(Files.newInputStream(inPath))) {
            Files.copy(in, outPath);
        }
    }
}
