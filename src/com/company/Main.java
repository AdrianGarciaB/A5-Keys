package com.company;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class Main {

    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        exercicio4();
    }

    private static void exercicio1(){
        String mensajesecreto = "hola que tal!!!";
        ClausSimetriques.getInstance().setClau("hola",256);
        byte[] mensajeencriptado = ClausSimetriques.getInstance().encryptData(mensajesecreto.getBytes());

        ClausSimetriques.getInstance().setClau("hola2",256);

        byte[] mensajedesencriptado = ClausSimetriques.getInstance().decryptData(mensajeencriptado);
        if (mensajedesencriptado != null) System.out.println(new String(mensajedesencriptado));
    }

    private static void exercicio2() throws IOException {
        byte[] fileencrypted = Files.readAllBytes(Paths.get("data/textamagat"));

        String clave;
        String mensaje;
        BufferedReader bufferedReader = new BufferedReader(new FileReader("data/clausA4.txt"));
        while ((clave = bufferedReader.readLine()) != null) {
            int keySize[] = new int[]{128, 192, 256};
            for (int i = 0; i < 3; i++) {
                ClausSimetriques.getInstance().setClau(clave, keySize[i]);
                if (ClausSimetriques.getInstance().decryptData(fileencrypted) != null) {
                    System.out.println("POSIBLE CLAVE ENCONTRADA: " + clave);
                    System.out.println("TAMAÑO DE LA CLAVE: " + keySize[i]);
                    System.out.println("MENSAJE: " + new String(ClausSimetriques.getInstance().decryptData(fileencrypted), "UTF8"));
                }
            }
        }

    }

    private static void exercicio3(){
        Scanner in = new Scanner(System.in);

        System.out.println("Texto a cifrar: ");
        String textoplano = in.nextLine();
        ClausAsimetriques.getInstance();
        byte[] textoencriptado = ClausAsimetriques.getInstance().encryptData(textoplano.getBytes());
        String textodesencriptado = new String(ClausAsimetriques.getInstance().decryptData(textoencriptado));
        System.out.println(new String(textoencriptado));
        System.out.println(textodesencriptado);
    }

    private static void exercicio4() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        FileInputStream is = new FileInputStream("data/.keystore");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        final String password = "usuario";
        keystore.load(is, password.toCharArray());

        System.out.println("Tipo de Keystore: "+keystore.getType());
        System.out.println("Numero de claves: " + keystore.size());
        System.out.print("Lista de alias: ");

        Collections.list(keystore.aliases()).forEach(s -> {
            System.out.print(s + " ");
        });

        //System.out.println("\nCertificat de " + keystore.aliases().nextElement() +": " + keystore.getCertificate(keystore.aliases().nextElement()));
        System.out.println("Algoritmo de cifrado: " + keystore.getKey(keystore.aliases().nextElement(), password.toCharArray()).getAlgorithm());

        SecretKey secretKey = new ClausSimetriques().setClau(1024).getsKey();
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        keystore.setEntry("simetrickey",skEntry, protParam);

        try (FileOutputStream fos = new FileOutputStream("data/.keystore")) {
            keystore.store(fos, password.toCharArray());
        }

        Scanner in = new Scanner(System.in);

        ClausAsimetriques clausAsimetriques = new ClausAsimetriques(1024);
        //System.out.println(clausAsimetriques.getPublicKey("/home/dam2a/public.cer"));

        System.out.println(clausAsimetriques.getPublicKey(keystore, "mykey", ""));

        byte[] firma = clausAsimetriques.getSignature("Hello world sign!", (PrivateKey) keystore.getKey("mykey", password.toCharArray()));
        System.out.println("Firma: " + Base64.getEncoder().encodeToString(firma));

        

    }

}