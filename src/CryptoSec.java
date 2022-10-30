import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

/**Implement helper method to create RSA Signature given private key ← working on it (Taha)
Implement helper method to verify RSA Signature given signature and public key 
 */

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
            e.printStackTrace();
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

    public KeyPair genECDHKeyPair() {
       try {
           ECGenParameterSpec ecAlgoSpec = new ECGenParameterSpec("secp256k1");
           KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH");
           keyGen.initialize(ecAlgoSpec);
           return keyGen.generateKeyPair();
       } catch (NoSuchAlgorithmException e) {
           System.out.println("Invalid algorithm specified for ECDH keygen");
           e.printStackTrace();
       } catch (InvalidAlgorithmParameterException e) {
           System.out.println("Invalid algorithm parameters specified for ECDH keygen");
           e.printStackTrace();
       }
       return null;
    }

    // TODO Key may be incorrect:
    public byte[] rsaEncrypt(byte[] msg, Key key) {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            return rsaCipher.doFinal(msg);
        } catch (InvalidKeyException e) {
            System.out.println("RSA encryption failed due to invalid key");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.out.println("RSA encryption failed due to invalid padding");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Encryption failed due to no such encryption algorithm existing");
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.out.println("RSA encryption failed due to invalid provider");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println("RSA encryption failed due to invalid block size");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.out.println("RSA encryption failed due to bad padding");
            e.printStackTrace();
        }
        return null;
    }

    public byte[] rsaSign(RSAPrivateKey privateKey, byte[] msg) {
        try {
            Signature rsaSig = Signature.getInstance("SHA256withRSA", "BC");
            rsaSig.initSign(privateKey);
            rsaSig.update(msg);
            return rsaSig.sign();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Signature algorithm specified not found");
            e.printStackTrace();
        } catch (SignatureException e) {
            System.out.println("Issue signing RSA");
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.out.println("Invalid security provider provided for RSA signature");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key specified for RSA signature");
            e.printStackTrace();
        }
        return null;
    }

    /** Generate shared secret Kab
    * @params privateKey - ECDH private key of party calling this function
    *         publicKey - ECDH public key of other party provided by party calling this function
    * return - byte[] of shared secret
    */
    public byte[] generateSharedSecret(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        try {
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
            keyAgree.init(privateKey);
            keyAgree.doPhase(publicKey, true);
            byte[] sharedSecret = keyAgree.generateSecret();
            // System.out.println("Shared secret: ", printHexBinary(sharedSecret));
            return sharedSecret;
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: No algorithm exists");
        } catch(InvalidKeyException e) {
            System.out.println("Error: Invlid Key");
        } catch(NoSuchProviderException e) {
            System.out.println("Error: No such provider exists");
        }
        return null;
    }

}
