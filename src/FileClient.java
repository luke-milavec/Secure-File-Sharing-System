/* FileClient provides all the client functionality regarding the file server */

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Scanner;

public class FileClient extends Client implements FileClientInterface {
    
    @Override
    public boolean connect(String server, int port, String username) {
        System.out.println("attempting to connect");

        try {
            sock = new Socket(server, port);
            output = new ObjectOutputStream(sock.getOutputStream());
            input = new ObjectInputStream(sock.getInputStream());

            // Check to see if the server's public key is cached or not, if not get the key sent by server
            // display it and ask user to verify it out-of-bound. If it is cached don't display, instead compare it
            // to see if the file server sent the same public key as the one that is cached.
            // If it is, continue with connection else disconnect and display a message saying that
            // the file server could not be verified.
            CryptoSec cs = new CryptoSec();
            Envelope pubKeyMsg = (Envelope)input.readObject();
            RSAPublicKey fsPubKey= (RSAPublicKey) pubKeyMsg.getObjContents().get(0);
            File serverKeys = new File("known_servers" + File.separator + pubKeyMsg.getMessage() +".public");

            if (serverKeys.exists()) {
                // Compare key sent by server to the cached one
                RSAPublicKey cachedFSPubKey = cs.readRSAPublicKey("known_servers" + File.separator + pubKeyMsg.getMessage());
                if(cs.byteArrToHexStr(fsPubKey.getEncoded()).equals(cs.byteArrToHexStr(cachedFSPubKey.getEncoded()))) {
                    System.out.println("The cached public key for this server matched the public key sent by " + server +
                            " at port " + port + ". Connecting...");
                } else {
                    disconnect();
                    System.out.println("Cached public key for server did not match the public key " +
                            server + " at port " + port + " provided. Disconnected. Type 'help' to see options.");
                    return false;
                }
            } else {
                System.out.println("No prior connection to this server found:");
                System.out.println("This file server's RSA public key in hex is:");
                System.out.println(cs.byteArrToHexStr(fsPubKey.getEncoded()));
                System.out.println("Verify with an admin or the server's creator to verify this is the correct " +
                        "file server public key.");
                System.out.println("Enter 'y' to verify that the public key is valid and to continue and connect" +
                        " to the file server or 'n' to end the session:");
                Scanner in = new Scanner(System.in);
                boolean validInput = false;
                while(!validInput) {
                    String userInput = in.nextLine();
                    if (userInput.equalsIgnoreCase("y")) {
                        // Create new directory if it doesn't exist
                        File knownServerDir = new File("known_servers");
                        if(!knownServerDir.exists() && !knownServerDir.mkdir()) {
                            System.out.println("Error creating " + knownServerDir);
                        }
                        String pubKeyFilePath = "known_servers" + File.separator + pubKeyMsg.getMessage();
                        if (cs.writePubKey(pubKeyFilePath, fsPubKey)) {
                            System.out.println("File Server's public key cached in " + pubKeyFilePath);
                        }
                        validInput = true;
                    } else if (userInput.equalsIgnoreCase("n")) {
                        disconnect();
                        System.out.println("Disconnected. Type 'help' to see options.");
                        return false;
                    } else {
                        System.out.println("Invalid input. Enter 'y' to verify that the public key is valid and" +
                                " connect to the file server or 'n' to end the session:");
                    }
                }
            }

            /** To establish a secure connection, a handshake is done.
             * Steps: After user clicks/types "connect to group/file server"
             * 1) ECDH keypair is generated
             * 2) Sign ECDH public key with RSA private key
             * 3) Send to server you want to connect with
             * 4) Repeat steps 1-3 for server to send to client
             * 5) Key Agreement - generation of Kab
             */

            // 1) ECDH keypair is generated
            KeyPair ecKeyPair = cs.genECDHKeyPair();
            RSAPrivateKey userRSAprivatekey = cs.readRSAPrivateKey(username);
            if (userRSAprivatekey == null) {
                System.out.println("Could not find " + username + "'s RSA private key.");
            }
            RSAPublicKey userRSApublickey = cs.readRSAPublicKey(username);
            if (userRSApublickey == null) {
                System.out.println("Could not find " + username + "'s RSA public key.");
            }
            // 2) Sign ECDH public key with RSA private key
            byte[] userPrivateECKeySig = cs.rsaSign(userRSAprivatekey, ecKeyPair.getPublic().getEncoded());
            // 3) Send to server you want to connect with
            Envelope connectRequest = new Envelope("SignatureForHandshake");
             // TODO confirm w/ Prof it is okay to send userPublic key unencrypted
            connectRequest.addObject(userRSApublickey); // So the server can verify the signature
            connectRequest.addObject(ecKeyPair.getPublic());
            connectRequest.addObject(userPrivateECKeySig);
            output.writeObject(connectRequest);

            /**
             * Server handshake part
             */
            Envelope serverHandshake = (Envelope)input.readObject();
            if(serverHandshake.getMessage().equals("FAIL")) {
                System.err.println("ERROR: Handshake Failed on server end; \nEither content is null or signature cannot be verified.");
                return false;
            } else if(serverHandshake.getMessage().equals("SignatureForHandshake")) {

                // Fetch content
                PublicKey serverECDHPubKey = (PublicKey) serverHandshake.getObjContents().get(0);
                byte [] serverECDHKeySig = (byte []) serverHandshake.getObjContents().get(1);
                if (serverECDHKeySig == null) {
                    System.err.println("ERROR: Signature from server is null");
                    return false;
                }
                // Must verify server signature
                Signature verifySig = Signature.getInstance("SHA256withRSA", "BC");
                verifySig.initVerify(fsPubKey);
                verifySig.update(serverECDHPubKey.getEncoded());
                if(!verifySig.verify(serverECDHKeySig)) {
                    System.err.println("ERROR: Signature from server cannot be verified");
                    return false;
                }

                // Generate Kab, shared secret between user and server
                Kab = cs.generateSharedSecret(ecKeyPair.getPrivate(), serverECDHPubKey);
//                System.out.println("client side shared secret: " + cs.byteArrToHexStr(Kab));
                // DEBUG: System.err.println("Shared secret: ", printHexBinary(Kab));

            } else {
                // Message received was neither "SignatureForHandshake" nor "FAIL"
                System.err.println("ERROR: Message received was neither SignatureForHandshake nor FAIL");
                return false;
            }

            System.out.println("Connected to " + server + " on port " + port);
            return true;
        }
        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean delete(String filename, UserToken token) {
        CryptoSec cs = new CryptoSec();
        String remotePath;
        if (filename.charAt(0)=='/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }
        Envelope env = new Envelope("DELETEF"); //Success
        env.addObject(remotePath);
        env.addObject(cs.encryptToken(token, Kab));
        try {
            output.writeObject(cs.encryptEnvelope(env, Kab));
            env = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

            if (env.getMessage().compareTo("OK")==0) {
                System.out.printf("File %s deleted successfully\n", filename);
            } else {
                System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
                return false;
            }
        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        }

        return true;
    }

    public boolean download(String sourceFile, String destFile, UserToken token) {
        CryptoSec cs = new CryptoSec();
        if (sourceFile.charAt(0)=='/') {
            sourceFile = sourceFile.substring(1);
        }

        File file = new File(destFile);
        try {


            if (!file.exists()) {
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);

                Envelope env = new Envelope("DOWNLOADF"); //Success
                env.addObject(sourceFile);
                env.addObject(cs.encryptToken(token, Kab));
                output.writeObject(cs.encryptEnvelope(env, Kab));

                env = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

                while (env.getMessage().compareTo("CHUNK")==0) {
                    fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
                    System.out.printf(".");
                    env = new Envelope("DOWNLOADF"); //Success
                    output.writeObject(cs.encryptEnvelope(env, Kab));
                    env = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);
                }
                fos.close();

                if(env.getMessage().compareTo("EOF")==0) {
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    env = new Envelope("OK"); //Success
                    output.writeObject(cs.encryptEnvelope(env, Kab));
                } else {
                    System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
                    file.delete();
                    return false;
                }
            }

            else {
                System.out.printf("Error couldn't create file %s\n", destFile);
                return false;
            }


        } catch (IOException e1) {

            System.out.printf("Error couldn't create file %s\n", destFile);
            return false;


        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        CryptoSec cs = new CryptoSec();
        try {
            Envelope message = null, e = null;
            //Tell the server to return the member list
            message = new Envelope("LFILES");
            message.addObject(cs.encryptToken(token, Kab)); //Add requester's token
            output.writeObject(cs.encryptEnvelope(message, Kab));

            e = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

            //If server indicates success, return the member list
            if(e.getMessage().equals("OK")) {
                return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group,
                          UserToken token) {

        CryptoSec cs = new CryptoSec();

        if (destFile.charAt(0)!='/') {
            destFile = "/" + destFile;
        }

        try {

            Envelope message = null, env = null;
            //Tell the server to return the member list
            message = new Envelope("UPLOADF");
            message.addObject(destFile);
            message.addObject(group);
            message.addObject(cs.encryptToken(token, Kab)); //Add requester's token
            output.writeObject(cs.encryptEnvelope(message, Kab));


            FileInputStream fis = new FileInputStream(sourceFile);

            env = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

            //If server indicates success, return the member list
            if(env.getMessage().equals("READY")) {
                System.out.printf("Meta data upload successful\n");

            } else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }


            do {
                byte[] buf = new byte[4096];
                if (env.getMessage().compareTo("READY")!=0) {
                    System.out.printf("Server error: %s\n", env.getMessage());
                    return false;
                }
                message = new Envelope("CHUNK");
                int n = fis.read(buf); //can throw an IOException
                if (n > 0) {
                    System.out.printf(".");
                } else if (n < 0) {
                    System.out.println("Read error");
                    return false;
                }

                message.addObject(buf);
                message.addObject(Integer.valueOf(n));

                output.writeObject(cs.encryptEnvelope(message, Kab));


                env = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);


            } while (fis.available()>0);

            //If server indicates success, return the member list
            if(env.getMessage().compareTo("READY")==0) {

                message = new Envelope("EOF");
                output.writeObject(cs.encryptEnvelope(message, Kab));

                env = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);
                if(env.getMessage().compareTo("OK")==0) {
                    System.out.printf("\nFile data upload successful\n");
                } else {

                    System.out.printf("\nUpload failed: %s\n", env.getMessage());
                    return false;
                }

            } else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }

        } catch(Exception e1) {
            System.err.println("Error: " + e1.getMessage());
            e1.printStackTrace(System.err);
            return false;
        }
        return true;
    }

}

