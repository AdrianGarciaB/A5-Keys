package com.company;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class Main {
    /*

    Ejercicios de la practica 5:
        El metodo exercicio5_1 corresponde al punto 1 de la practica.
        El metodo exercicio5_2 corresponde al punto 2 de la practica.

     */
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        exercicio5_1();
        exercicio5_2();
    }

    private static void ejercicio5_1_1(){
        Scanner in = new Scanner(System.in);

        System.out.println("Texto a cifrar: ");
        String textoplano = in.nextLine();
        byte[] textoencriptado = ClausAsimetriques.getInstance().encryptData(textoplano.getBytes());
        String textodesencriptado = new String(ClausAsimetriques.getInstance().decryptData(textoencriptado));
        System.out.println("Texto encriptado: " + new String(textoencriptado));
        System.out.println("Texto desencriptado: " + textodesencriptado);
        System.out.println("Formato clave publica: " + ClausAsimetriques.getInstance().getPublic().getFormat());
        System.out.println("Formato clave privada: " + ClausAsimetriques.getInstance().getPrivate().getFormat());
        System.out.println("Algoritmo de las claves: " + ClausAsimetriques.getInstance().getPublic().getAlgorithm());
    }

    private static void exercicio5_1() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        // Punto 1 subpunto 1
        ejercicio5_1_1();


        // Punto 1 subpunto 2
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
        System.out.println();

        System.out.println("\nCertificat de " + keystore.aliases().nextElement() +": " + keystore.getCertificate(keystore.aliases().nextElement()));
        System.out.println("Algoritmo de cifrado: " + keystore.getKey(keystore.aliases().nextElement(), password.toCharArray()).getAlgorithm());

        SecretKey secretKey = new ClausSimetriques().setClau(1024).getsKey();
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        keystore.setEntry("simetrickey",skEntry, protParam);

        try (FileOutputStream fos = new FileOutputStream("data/.keystore")) {
            keystore.store(fos, password.toCharArray());
        }

        // Punto 1 subpunto 3
        Scanner in = new Scanner(System.in);
        ClausAsimetriques clausAsimetriques = new ClausAsimetriques(1024);
        System.out.println(clausAsimetriques.getPublicKey("/home/dam2a/public.cer"));

        // Punto 1 subpunto 4
        PublicKey mykey = clausAsimetriques.getPublicKey(keystore, "mykey", "");
        System.out.println(mykey);

        // Punto 1 subpunto 5
        byte[] firma = clausAsimetriques.getSignature("Hello world sign!", (PrivateKey) keystore.getKey("mykey", password.toCharArray()));
        System.out.println("Firma: " + Base64.getEncoder().encodeToString(firma));

        // Punto 1 subpunto 6
        boolean firmavalida = clausAsimetriques.verifySignature("Hello world sign!", firma, mykey);
        System.out.println("La firma " + (firmavalida ? "es valida.":"no es valida."));

    }
    private static void exercicio5_2() throws NoSuchAlgorithmException {

        ClausEmbolcallades clausEmbolcalladesA = new ClausEmbolcallades();
        ClausEmbolcallades clausEmbolcalladesB = new ClausEmbolcallades();
        clausEmbolcalladesA.generateKeys();
        clausEmbolcalladesB.generateKeys();

        String mensaje = "Mensaje secreto para B";
        byte[][] mensajeparaB = clausEmbolcalladesA.encryptWrappedData(mensaje.getBytes(), clausEmbolcalladesB.getPublicKey());

        String mensajeDescodificado = new String(clausEmbolcalladesB.decryptWrappedData(mensajeparaB));
        System.out.println(mensajeDescodificado);


    }

}
