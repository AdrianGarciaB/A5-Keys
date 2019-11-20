package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class ClausEmbolcallades {
    KeyPair keyPair;
    SecretKey secretKey;


    public void generateKeys() throws NoSuchAlgorithmException {
        // Generamos la clave simetrica
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        secretKey = kgen.generateKey();

        // Generamos nuestras claves asmietricas
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        keyPair = keyPairGenerator.genKeyPair();
    }

    public PublicKey getPublicKey(){
        return keyPair.getPublic();
    }


    public byte[][] encryptWrappedData(byte[] data, PublicKey publicKey) {
        byte[][] encWrappedData = new byte[2][];
        try {
            // Con la clave simetrica ciframos los datos que queremos enviar.
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encMsg = cipher.doFinal(data);

            // Con la clave publica de B, ciframos la clave simetrica.
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] encKey = cipher.wrap(secretKey);

            // Guardamos y enviamos.
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    public byte[] decryptWrappedData(byte[][] data) {
        byte[] decryMsg = new byte[1];
        try {
            // Desciframos la clave simetrica con nuestra clave privada que hemos generado con el sistema asimetrico.
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
            SecretKey secretKey = (SecretKey) cipher.unwrap(data[1], "AES", Cipher.SECRET_KEY);

            // Desciframos el mensaje secreto con nuestra clave simetrica.
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            decryMsg = cipher.doFinal(data[0]);

        } catch (Exception  ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return decryMsg;
    }
}
