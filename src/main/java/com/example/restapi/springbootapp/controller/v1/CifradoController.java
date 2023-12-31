package com.example.restapi.springbootapp.controller.v1;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.validation.Valid;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.restapi.springbootapp.dto.ArchivoNormal;
import com.example.restapi.springbootapp.dto.DatoNormal;
import com.example.restapi.springbootapp.dto.Datos;
import com.example.restapi.springbootapp.utils.Blowfish;
import com.example.restapi.springbootapp.utils.DesedeCrypter;
import com.example.restapi.springbootapp.utils.EncriptadorAES;
import com.example.restapi.springbootapp.utils.EncriptadorBase64;
import com.example.restapi.springbootapp.utils.EncriptadorIDEA;
import com.example.restapi.springbootapp.utils.EncriptadorIDEAFiles;
import com.example.restapi.springbootapp.utils.EncriptadorIDEAFiles.Mode;
import com.example.restapi.springbootapp.utils.EncriptadorMD5;
import com.example.restapi.springbootapp.utils.EncriptadorRC6;
import com.example.restapi.springbootapp.utils.RSAEncryption;
import com.example.restapi.springbootapp.utils.Uploads;
import com.example.restapi.springbootapp.utils.AES.FileEncrypterDecrypter;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.servers.Server;

/**
 *
 * @author Jccm.17
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@OpenAPIDefinition(servers = { @Server(url = "http://encriptacion-sess.us-east-1.elasticbeanstalk.com/"),
        @Server(url = "http://localhost:8080") }, info = @Info(title = "Encriptacion Spring Boot API", version = "v1", description = "A project using Spring Boot with Swagger-UI enabled", license = @License(name = "MIT License", url = "#"), contact = @Contact(url = "https://www.jccm.xyz", name = "SESS")))
@RestController
@RequestMapping("v1/")
public class CifradoController {
    Logger logger = LogManager.getLogger(CifradoController.class);

    private final Path root = Paths.get("uploads");
    final String claveEncriptacion = "cifrado128AES25!";
    Uploads f = new Uploads();
    EncriptadorBase64 base_64 = new EncriptadorBase64();
    EncriptadorAES aes = new EncriptadorAES();
    FileEncrypterDecrypter aesFile = new FileEncrypterDecrypter();
    EncriptadorMD5 md5 = new EncriptadorMD5();
    DesedeCrypter des3 = new DesedeCrypter();
    EncriptadorIDEA idea = new EncriptadorIDEA(claveEncriptacion);
    EncriptadorIDEAFiles ideaFile = new EncriptadorIDEAFiles();
    Blowfish blowFish = new Blowfish();
    RSAEncryption rsa = new RSAEncryption();
    // Diffiehellman encriptado = new Diffiehellman();
    // Diffiehellman desencriptado = new Diffiehellman();
    EncriptadorRC6 rc6 = new EncriptadorRC6();

    @Operation(summary = "Retorna Texto en cifrado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Operacion exitosa", content = @Content(schema = @Schema(type = "object"))) })
    @PostMapping(value = "encriptar", produces = { "application/json;charset=UTF-8" })
    public ResponseEntity<?> encriptar(@Valid @RequestBody DatoNormal data) {
        Map<String, Object> response = new HashMap<>();
        String text = "";
        logger.info("texto a cifrar: " + data.getTextoNormal());
        logger.info("Metodo de cifrado: " + data.getMetodo());
        try {
            switch (data.getMetodo()) {
                case "BASE64":
                    response.put("textoCifrado", Base64.getEncoder().encodeToString(data.getTextoNormal().getBytes()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-1":
                    response.put("textoCifrado", aes.encriptar(data.getTextoNormal(), claveEncriptacion, "SHA-1"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-256":
                    response.put("textoCifrado", aes.encriptar(data.getTextoNormal(), claveEncriptacion, "SHA-256"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-384":
                    response.put("textoCifrado", aes.encriptar(data.getTextoNormal(), claveEncriptacion, "SHA-384"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-512":
                    response.put("textoCifrado", aes.encriptar(data.getTextoNormal(), claveEncriptacion, "SHA-512"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "MD5":
                    response.put("textoCifrado", md5.encode(data.getTextoNormal()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "3DES":
                    response.put("textoCifrado", des3.encrypt(data.getTextoNormal()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "IDEA":
                    response.put("textoCifrado", idea.encrypt(data.getTextoNormal()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "BLOWFISH":
                    response.put("textoCifrado", blowFish.enc(data.getTextoNormal()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "RSA":
                    response.put("textoCifrado", rsa.encriptar(data.getTextoNormal()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "DIFFIEHELLMAN":
                    // encriptado.encryptAndSendMessage(data.getTextoNormal(), desencriptado);
                    // desencriptado.whisperTheSecretMessage();
                    response.put("textoCifrado", data.getTextoNormal());
                    response.put("metodo", data.getMetodo());
                    break;
                case "RC6":
                    byte[] textBytes = data.getTextoNormal().getBytes();
                    response.put("textoCifrado", rc6.encrypt(textBytes));
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
    @PostMapping(value = "desencriptar", produces = { "application/json;charset=UTF-8" })
    public ResponseEntity<?> desencriptar(@Valid @RequestBody Datos data) {
        Map<String, Object> response = new HashMap<>();
        String text = "";
        logger.info("texto a descifrar: " + data.getTextoCifrado());
        logger.info("Metodo de descifrado: " + data.getMetodo());
        try {
            switch (data.getMetodo()) {
                case "BASE64":
                    byte[] decodedBytes = Base64.getUrlDecoder().decode(data.getTextoCifrado());
                    String decodedUrl = new String(decodedBytes);
                    response.put("textoDescifrado", decodedUrl);
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-1":
                    response.put("textoDescifrado",
                            aes.desencriptar(data.getTextoCifrado(), claveEncriptacion, "SHA-1"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-256":
                    response.put("textoDescifrado",
                            aes.desencriptar(data.getTextoCifrado(), claveEncriptacion, "SHA-256"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-384":
                    response.put("textoDescifrado",
                            aes.desencriptar(data.getTextoCifrado(), claveEncriptacion, "SHA-384"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "AES-512":
                    response.put("textoDescifrado",
                            aes.desencriptar(data.getTextoCifrado(), claveEncriptacion, "SHA-512"));
                    response.put("metodo", data.getMetodo());
                    break;
                case "MD5":
                    response.put("textoDescifrado", md5.decode(data.getTextoCifrado()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "3DES":
                    response.put("textoDescifrado", des3.decrypt(data.getTextoCifrado()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "IDEA":
                    response.put("textoDescifrado", idea.decrypt(data.getTextoCifrado()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "BLOWFISH":
                    response.put("textoDescifrado", blowFish.dec(data.getTextoCifrado()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "RSA":
                    response.put("textoDescifrado", rsa.desencriptar(data.getTextoCifrado()));
                    response.put("metodo", data.getMetodo());
                    break;
                case "RC6":
                    byte[] textBytes = data.getTextoCifrado().getBytes();
                    response.put("textoDescifrado", rc6.decrypt(textBytes));
                    response.put("metodo", data.getMetodo());
                    break;
                default:
                    response.put("textoDescifrado", text);
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
    public ResponseEntity<?> encriptarArchivo(@ModelAttribute ArchivoNormal data) throws Exception {
        String path = "uploads/";
        String ext = FilenameUtils.getExtension(data.getArchivo().getOriginalFilename()); // returns "txt"
        logger.info("ext: " + ext);
        String nameFileOut = "file_encrypt_" + data.getMetodo() + "." + ext;

        // f.eliminarTodo("uploads");
        f.eliminar("uploads/" + nameFileOut);
        String nameFile = UUID.randomUUID() + data.getArchivo().getOriginalFilename();
        Files.copy(data.getArchivo().getInputStream(), this.root.resolve(nameFile));
        path = path + nameFile;
        switch (data.getMetodo()) {
            case "BASE64":
                base_64.encodeFile(path, "uploads/" + nameFileOut);
                break;
            case "AES-1":
                File fileinAES = new File(path);
                aesFile.encryptFile(fileinAES, "uploads/" + nameFileOut, claveEncriptacion, "SHA-1");
                break;
            case "AES-256":
                File fileinAES256 = new File(path);
                aesFile.encryptFile(fileinAES256, "uploads/" + nameFileOut, claveEncriptacion, "SHA-256");
                break;
            case "AES-384":
                File fileinAES384 = new File(path);
                aesFile.encryptFile(fileinAES384, "uploads/" + nameFileOut, claveEncriptacion, "SHA-384");
                break;
            case "AES-512":
                File fileinAES512 = new File(path);
                aesFile.encryptFile(fileinAES512, "uploads/" + nameFileOut, claveEncriptacion, "SHA-512");
                break;
            case "IDEA":
                ideaFile.cryptFile(path, "uploads/" + nameFileOut, claveEncriptacion, true, Mode.ECB);
                break;
            case "3DES":
                File fileout = new File("uploads/" + nameFileOut);
                File filein = new File(path);
                des3.encryptFile(filein, fileout);
                break;
            case "BLOWFISH":
                blowFish.blowfishEncrypt(path, "uploads/" + nameFileOut);
                break;
            case "RSA":
                File fileinRSA = new File(path);
                File fileoutRSA = new File("uploads/" + nameFileOut);
                rsa.encriptarArchivo(fileinRSA, fileoutRSA);
                break;
            case "RC6":
                File fileoutRC6 = new File("uploads/" + nameFileOut);
                File fileinRC6 = new File(path);
                rc6.encryptFile(fileinRC6, fileoutRC6, claveEncriptacion);
                break;
            default:
                break;
        }
        f.eliminar("uploads/" + nameFile);
        logger.info("File Out: " + nameFileOut);
        HttpHeaders header = new HttpHeaders();
        header.add(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=" + nameFileOut);
        header.add("Cache-Control", "no-cache, no-store, must-revalidate");
        header.add("Pragma", "no-cache");
        header.add("Expires", "0");
        File file = new File("uploads/" + nameFileOut);
        Path pathout = Paths.get(file.getAbsolutePath());
        ByteArrayResource resource = new ByteArrayResource(Files.readAllBytes(pathout));
        // f.eliminar("uploads/" + nameFileOut);
        return ResponseEntity.ok()
                .headers(header)
                .contentLength(file.length())
                .contentType(MediaType.parseMediaType("application/octet-stream"))
                .body(resource);
    }

    @Operation(summary = "Retorna Archivo descifrado")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Operacion exitosa", content = @Content(schema = @Schema(type = "object"))) })
    @PostMapping(value = "desencriptar/archivo", consumes = "multipart/form-data")
    public ResponseEntity<?> desencriptarArchivo(@ModelAttribute ArchivoNormal data) throws Exception {
        String path = "uploads/";
        String ext = FilenameUtils.getExtension(data.getArchivo().getOriginalFilename()); // returns "txt"
        logger.info("ext: " + ext);
        String nameFileOut = "file_decrypt_" + data.getMetodo() + "." + ext;

        String nameFile = UUID.randomUUID() + data.getArchivo().getOriginalFilename();
        // f.eliminarTodo("uploads");
        f.eliminar("uploads/" + nameFileOut);
        Files.copy(data.getArchivo().getInputStream(), this.root.resolve(nameFile));
        path = path + nameFile;
        switch (data.getMetodo()) {
            case "BASE64":
                base_64.decodeFile(path, "uploads/" + nameFileOut);
                break;
            case "AES-1":
                File fileinAES = new File(path);
                aesFile.decryptFile(fileinAES, "uploads/" + nameFileOut, claveEncriptacion, "SHA-1");
                break;
            case "AES-256":
                File fileinAES256 = new File(path);
                aesFile.decryptFile(fileinAES256, "uploads/" + nameFileOut, claveEncriptacion, "SHA-256");
                break;
            case "AES-384":
                File fileinAES384 = new File(path);
                aesFile.decryptFile(fileinAES384, "uploads/" + nameFileOut, claveEncriptacion, "SHA-384");
                break;
            case "AES-512":
                File fileinAES512 = new File(path);
                aesFile.decryptFile(fileinAES512, "uploads/" + nameFileOut, claveEncriptacion, "SHA-512");
                break;
            case "IDEA":
                ideaFile.cryptFile(path, "uploads/" + nameFileOut, claveEncriptacion, false, Mode.ECB);
                break;
            case "3DES":
                File fileout = new File("uploads/" + nameFileOut);
                File filein = new File(path);
                des3.decryptFile(filein, fileout);
                break;
            case "BLOWFISH":
                blowFish.blowfishDecrypt(path, "uploads/" + nameFileOut);
                break;
            case "RSA":
                File fileinRSA = new File(path);
                rsa.desencriptarArchivo(fileinRSA, "uploads/" + nameFileOut);
                break;
            case "RC6":
                File fileinRC6 = new File(path);
                rc6.decryptFile(fileinRC6, "uploads/" + nameFileOut, claveEncriptacion);
                break;
            default:
                break;
        }
        f.eliminar("uploads/" + nameFile);
        logger.info("File Out: " + nameFileOut);
        HttpHeaders header = new HttpHeaders();
        header.add(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=" + nameFileOut);
        header.add("Cache-Control", "no-cache, no-store, must-revalidate");
        header.add("Pragma", "no-cache");
        header.add("Expires", "0");
        File file = new File("uploads/" + nameFileOut);
        Path pathout = Paths.get(file.getAbsolutePath());
        ByteArrayResource resource = new ByteArrayResource(Files.readAllBytes(pathout));
        return ResponseEntity.ok()
                .headers(header)
                .contentLength(file.length())
                .contentType(MediaType.parseMediaType("application/octet-stream"))
                .body(resource);
    }

}