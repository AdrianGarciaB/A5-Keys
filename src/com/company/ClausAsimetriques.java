package com.company;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClausAsimetriques {
    private static ClausAsimetriques clausAsimetriques;
    private KeyPair keys;

    public static ClausAsimetriques getInstance(){
        if (clausAsimetriques == null) clausAsimetriques = new ClausAsimetriques(1024);
        return clausAsimetriques;
    }

    public void generatePairKey(int len){
        keys = randomGenerate(len);
    }

    ClausAsimetriques(int len){keys = randomGenerate(len);}

    public KeyPair randomGenerate(int len) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public byte[] encryptData(byte[] data) {
        byte[] encryptedData = null;
        PublicKey pub = getPublic();
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public byte[] decryptData(byte[] data) {
        byte[] decryptedData = null;
        PrivateKey pub = getPrivate();
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return decryptedData;
    }

    public PublicKey getPublic(){
        return keys.getPublic();
    }

    public PrivateKey getPrivate(){
        return keys.getPrivate();
    }

    public PublicKey getPublicKey(String fitxer) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(fitxer);
        Certificate cer = certificateFactory.generateCertificate(is);
        return cer.getPublicKey();
    }

    public PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) throws KeyStoreException {
        return ks.getCertificate(alias).getPublicKey();
    }

    public byte[] getSignature(String datos, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithDSA");
        signature.initSign(privateKey);
        signature.update(datos.getBytes());
        byte[] signaturebyte = signature.sign();

        return signaturebyte;
    }


}
