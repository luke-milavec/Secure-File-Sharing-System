import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoSec {
    CryptoSec() {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    public KeyPair genRSAKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            SecureRandom randSrc = new SecureRandom();
            gen.initialize(2048, randSrc);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("There was error generating RSA keypair");
            e.printStackTrace();
        }
        return null;
    }

    public RSAPublicKey readRSAPublicKey(String fileName) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader = new PemReader(new FileReader(fileName));
            byte[] pubBytes = pemReader.readPemObject().getContent();
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error finding RSA");
        } catch (FileNotFoundException e) {
            System.out.println("Unable to find RSA public key for " + fileName);
        } catch (IOException e) {
            System.out.println("Error reading in public key");
        } catch (InvalidKeySpecException e) {
            System.out.println("The public key encoding was improperly configured so turning it back into a" +
                    " RSAPublicKey key failed");
        }
        return null;
    }

    public RSAPrivateKey readRSAPrivateKey(String fileName) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader = new PemReader(new FileReader(fileName + ".private"));
            byte[] privBytes = pemReader.readPemObject().getContent();
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error finding RSA algorithm");
        } catch (FileNotFoundException e) {
            System.out.println("Unable to find RSA private key for " + fileName);
        } catch (IOException e) {
            System.out.println("Error reading in private key");
        } catch (InvalidKeySpecException e) {
            System.out.println("The private key encoding was improperly configured so turning it back into a" +
                    " RSAPrivateKey key failed");
            e.printStackTrace();
        }

        return null;
    }

    public boolean writeKeyPair(String username, KeyPair keypair) {
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
            System.out.println("Error writing key to file.");
        }
        return false;
    }

    public boolean writePubKey(String filename, RSAPublicKey pubKey) {
        try {
            // Write public key to file
            String pubFilename = filename + ".public";
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(pubFilename)));
            pemWriter.writeObject(new PemObject("RSA PUBLIC KEY", pubKey.getEncoded()));
            pemWriter.close();
            return true;
        } catch (IOException e) {
            System.out.println("Error writing public key to file.");
            e.printStackTrace();
        }
        return false;
    }

    public String byteArrToHexStr(byte [] byteArr) {
        StringBuilder hexStr = new StringBuilder();
        for (byte b: byteArr) {
            hexStr.append(String.format("%02x", b));
        }
        return hexStr.toString();
    }

    public boolean writeStrToFile(String filename, String str) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(filename + ".txt"));
            bw.write(str);
            bw.close();
            return true;
        } catch (IOException e) {
            System.out.println("There was an issue writing string to " + filename + ".txt");
        }
        return false;
    }
}
