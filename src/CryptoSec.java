import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoSec {
    CryptoSec() {

    }
    public KeyPair genRSAKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("There was error generating RSA keypair");
        }
        return null;
    }

    public RSAPublicKey readRSAPublicKey(String username) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader = new PemReader(new FileReader(username + ".public"));
            byte[] pubBytes = pemReader.readPemObject().getContent();
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error finding RSA");
        } catch (FileNotFoundException e) {
            System.out.println("Unable to find RSA public key for " + username);
        } catch (IOException e) {
            System.out.println("Error reading in public key");
        } catch (InvalidKeySpecException e) {
            System.out.println("The public key encoding was improperly configured so turning it back into a" +
                    " RSAPublicKey key failed");
        }
        return null;
    }

    public RSAPrivateKey readRSAPrivateKey(String username) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader = new PemReader(new FileReader(username + ".private"));
            byte[] privBytes = pemReader.readPemObject().getContent();
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error finding RSA algorithm");
        } catch (FileNotFoundException e) {
            System.out.println("Unable to find RSA private key for " + username);
        } catch (IOException e) {
            System.out.println("Error reading in private key");
        } catch (InvalidKeySpecException e) {
            System.out.println("The public key encoding was improperly configured so turning it back into a" +
                    " RSAPrivateKey key failed");
            e.printStackTrace();
        }

        return null;
    }

    public boolean writeKey(String username, KeyPair keypair) {
        try {
            // Write public key to file
            String pubFilename = username + ".public";
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(pubFilename)));
            pemWriter.writeObject(new PemObject("RSA PUBLIC KEY", keypair.getPublic().getEncoded()));
            pemWriter.close();

            // Write private key to file
            String privFilename = username + ".private";
            pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(privFilename)));
            pemWriter.writeObject(new PemObject("RSA PRIVATE KEY", keypair.getPrivate().getEncoded()));
            pemWriter.close();

            return true;
        } catch (IOException e) {
            System.out.println("Error writing key to file");
        }
        return false;
    }




}
