/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class FileThread extends Thread {
    private final Socket socket;
    String fsName;
    CryptoSec cs;

    private byte[] Kab;

    public FileThread(Socket _socket, String _fsName) {
        socket = _socket;
        fsName = _fsName;
        cs = new CryptoSec();
    }

    public void run() {
        boolean proceed = true;
        try {
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response;


            RSAPublicKey gsPubKey = cs.readRSAPublicKey("gs");

            // conduct Handshake A
            if (!handshake(input, output)) {
                System.out.println("Error connecting, verification failed.");
            } else {
                do {
                    Message msg = (Message) input.readObject();
                    Envelope e = cs.decryptEnvelopeMessage(msg, Kab);
                    System.out.println("Request received: " + e.getMessage());

                    // Handler to list files that this user is allowed to see
                    if(e.getMessage().equals("LFILES")) {
                        if(e.getObjContents().size() < 1) {  // no token sent
                            response = new Envelope("FAIL-BADCONTENTS");
                        } else if (e.getObjContents().get(0) == null){ // if the token is null
                            response = new Envelope("FAIL-BADTOKEN");
                        } else {
                            UserToken token = cs.decryptSignedToken( (SignedToken) e.getObjContents().get(0),gsPubKey);
                            if(tokenTimeValid(token)){
                                List<String> allowedGroups = token.getGroups();
                                List<ShareFile> serverFileList = FileServer.fileList.getFiles();

                                List<String> fileRetList = new ArrayList<>(); // list to return
                                for (ShareFile sf : serverFileList) {
                                    if (allowedGroups.contains(sf.getGroup())) { // user is allowed to access file
                                        fileRetList.add(sf.getPath()); // Return a list of file paths which is essentially the name of the file?
                                    }
                                }
                                System.out.println("Sending list of files");
                                response = new Envelope("OK");
                                response.addObject(fileRetList);
                            } else {
                                response = new Envelope("FAIL-EXPIREDTOKEN");
                            }
                        }
                        output.writeObject(cs.encryptEnvelope(response, Kab));
                    }
                    if(e.getMessage().equals("UPLOADF")) {

                        if(e.getObjContents().size() < 3) {
                            response = new Envelope("FAIL-BADCONTENTS");
                        } else {
                            if(e.getObjContents().get(0) == null) {
                                response = new Envelope("FAIL-BADPATH");
                            }
                            if(e.getObjContents().get(1) == null) {
                                response = new Envelope("FAIL-BADGROUP");
                            }
                            if(e.getObjContents().get(2) == null) {
                                response = new Envelope("FAIL-BADTOKEN");
                            } else {
                                String remotePath = (String)e.getObjContents().get(0);
                                String group = (String)e.getObjContents().get(1);
                                UserToken yourToken = cs.decryptSignedToken( (SignedToken) e.getObjContents().get(2),gsPubKey);
                                if(!tokenTimeValid(yourToken)){
                                    response = new Envelope("FAIL-EXPIREDTOKEN");
                                } else if (FileServer.fileList.checkFile(remotePath)) {
                                    System.out.printf("Error: file already exists at %s\n", remotePath);
                                    response = new Envelope("FAIL-FILEEXISTS"); //Success
                                } else if (!yourToken.getGroups().contains(group)) {
                                    System.out.printf("Error: user missing valid token for group %s\n", group);
                                    response = new Envelope("FAIL-UNAUTHORIZED"); //Success
                                } else  {
                                    File file = new File("shared_files/"+remotePath.replace('/', '_'));
                                    file.createNewFile();
                                    FileOutputStream fos = new FileOutputStream(file);
                                    System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

                                    response = new Envelope("READY"); //Success
                                    output.writeObject(cs.encryptEnvelope(response, Kab));

                                    msg = (Message) input.readObject();
                                    e = cs.decryptEnvelopeMessage(msg, Kab);

                                    while (e.getMessage().compareTo("CHUNK")==0) {
                                        fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
                                        response = new Envelope("READY"); //Success
                                        output.writeObject(cs.encryptEnvelope(response, Kab));
                                        msg = (Message) input.readObject();
                                        e = cs.decryptEnvelopeMessage(msg, Kab);
                                    }

                                    if(e.getMessage().compareTo("EOF")==0) {
                                        System.out.printf("Transfer successful file %s\n", remotePath);
                                        FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
                                        response = new Envelope("OK"); //Success
                                    } else {
                                        System.out.printf("Error reading file %s from client\n", remotePath);
                                        response = new Envelope("ERROR-TRANSFER"); //Success
                                    }
                                    fos.close();
                                }
                            }
                        }

                        output.writeObject(cs.encryptEnvelope(response, Kab));
                    } else if (e.getMessage().compareTo("DOWNLOADF")==0) {

                        String remotePath = (String)e.getObjContents().get(0);
                        //UserToken t = cs.decryptTokenMessage((Message) e.getObjContents().get(1), Kab, gsPubKey);
                        UserToken t= cs.decryptSignedToken( (SignedToken) e.getObjContents().get(1),gsPubKey);
                        ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                        if(!tokenTimeValid(t)){
                            System.out.println("Error: Token Expired");
                            e = new Envelope("FAIL-EXPIREDTOKEN");
                            output.writeObject(cs.encryptEnvelope(e, Kab));
                        }else if (sf == null) {
                            System.out.printf("Error: File %s doesn't exist\n", remotePath);
                            e = new Envelope("ERROR_FILEMISSING");
                            output.writeObject(cs.encryptEnvelope(e, Kab));

                        } else if (!t.getGroups().contains(sf.getGroup())) {
                            System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                            e = new Envelope("ERROR_PERMISSION");
                            output.writeObject(cs.encryptEnvelope(e, Kab));
                        } else {

                            try {
                                File f = new File("shared_files/_"+remotePath.replace('/', '_'));
                                if (!f.exists()) {
                                    System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                    e = new Envelope("ERROR_NOTONDISK");
                                    output.writeObject(cs.encryptEnvelope(e, Kab));

                                } else {
                                    FileInputStream fis = new FileInputStream(f);

                                    do {
                                        byte[] buf = new byte[4096];
                                        if (e.getMessage().compareTo("DOWNLOADF")!=0) {
                                            System.out.printf("Server error: %s\n", e.getMessage());
                                            break;
                                        }
                                        e = new Envelope("CHUNK");
                                        int n = fis.read(buf); //can throw an IOException
                                        if (n > 0) {
                                            System.out.printf(".");
                                        } else if (n < 0) {
                                            System.out.println("Read error");

                                        }

                                        e.addObject(buf);
                                        e.addObject(Integer.valueOf(n));

                                        output.writeObject(cs.encryptEnvelope(e, Kab));

                                        msg = (Message) input.readObject();
                                        e = cs.decryptEnvelopeMessage(msg, Kab);


                                    } while (fis.available()>0);

                                    //If server indicates success, return the member list
                                    if(e.getMessage().compareTo("DOWNLOADF")==0) {

                                        e = new Envelope("EOF");
                                        output.writeObject(cs.encryptEnvelope(e, Kab));

                                        msg = (Message) input.readObject();
                                        e = cs.decryptEnvelopeMessage(msg, Kab);
                                        if(e.getMessage().compareTo("OK")==0) {
                                            System.out.printf("File data upload successful\n");
                                        } else {

                                            System.out.printf("Upload failed: %s\n", e.getMessage());

                                        }

                                    } else {

                                        System.out.printf("Upload failed: %s\n", e.getMessage());

                                    }
                                    fis.close();
                                }
                            } catch(Exception e1) {
                                System.err.println("Error: " + e.getMessage());
                                e1.printStackTrace(System.err);

                            }
                        }
                    } else if (e.getMessage().compareTo("DELETEF")==0) {

                        String remotePath = (String)e.getObjContents().get(0);
                        //UserToken t = cs.decryptTokenMessage((Message) e.getObjContents().get(1), Kab, gsPubKey);
                        UserToken t = cs.decryptSignedToken( (SignedToken) e.getObjContents().get(1),gsPubKey);
                        ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                        if(!tokenTimeValid(t)){
                            e = new Envelope("FAIL-EXPIREDTOKEN");
                        }else if (sf == null) {
                            System.out.printf("Error: File %s doesn't exist\n", remotePath);
                            e = new Envelope("ERROR_DOESNTEXIST");
                        } else if (!t.getGroups().contains(sf.getGroup())) {
                            System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                            e = new Envelope("ERROR_PERMISSION");
                        } else {

                            try {
                                File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

                                if (!f.exists()) {
                                    System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                    e = new Envelope("ERROR_FILEMISSING");
                                } else if (f.delete()) {
                                    System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
                                    FileServer.fileList.removeFile("/"+remotePath);
                                    e = new Envelope("OK");
                                } else {
                                    System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
                                    e = new Envelope("ERROR_DELETE");
                                }


                            } catch(Exception e1) {
                                System.err.println("Error: " + e1.getMessage());
                                e1.printStackTrace(System.err);
                                e = new Envelope(e1.getMessage());
                            }
                        }
                        output.writeObject(cs.encryptEnvelope(e, Kab));

                    } else if(e.getMessage().equals("DISCONNECT")) {
                        socket.close();
                        proceed = false;
                    }
                } while(proceed);
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private boolean handshake(final ObjectInputStream input, final ObjectOutputStream output) {
        try {
//            System.out.println(fsName);
            // Send over group server's Public Key as RSAPublicKey so that user can verify it
            RSAPublicKey fsPubKey = cs.readRSAPublicKey(fsName);
            Envelope resKey = new Envelope(fsName + "_pub_key");
            resKey.addObject(fsPubKey);
            output.writeObject(resKey);

            // Handshake
            Envelope signedRSA = (Envelope)input.readObject(); // user sent ECDH signed key
            if(signedRSA.getMessage().equals("SignatureForHandshake")) {
                RSAPublicKey userRSApublickey = (RSAPublicKey) signedRSA.getObjContents().get(0);
                PublicKey userECDHPubKey = (PublicKey) signedRSA.getObjContents().get(1);
                byte[] UserECDHpubKeySigned = (byte[]) signedRSA.getObjContents().get(2);

                // Initialize response envelope
                Envelope res;
                // Checks for if any contents are null
                if(userRSApublickey == null || userECDHPubKey == null || UserECDHpubKeySigned == null) {
                    res = new Envelope("FAIL");
                    res.addObject(null);
                    output.writeObject(res);
                } else {
                    Signature verifySig = Signature.getInstance("SHA256withRSA", "BC");
                    verifySig.initVerify(userRSApublickey);
                    verifySig.update(userECDHPubKey.getEncoded());
                    // If false, this user did NOT sign the message contents
                    if(!verifySig.verify(UserECDHpubKeySigned)) {
                        res = new Envelope("FAIL");
                        res.addObject(null);
                        output.writeObject(res);
                        return false;
                    } else {
                        // Generate ECDH keypair
                        KeyPair ECDHkeys = cs.genECDHKeyPair();
                        PublicKey ECDHpubkey = ECDHkeys.getPublic();
                        PrivateKey ECDHprivkey = ECDHkeys.getPrivate();

                        // Sign ECDH public key with RSA private key of file server
                        RSAPrivateKey serverRSAprivatekey = cs.readRSAPrivateKey(fsName);
                        byte[] serverPrivateECDHKeySig = cs.rsaSign(serverRSAprivatekey, ECDHpubkey.getEncoded());

                        // Send public key to user
                        res = new Envelope("SignatureForHandshake");
                        res.addObject(ECDHpubkey); // added this so user gets access to server's ecdh pubkey since it is not possible for the user to derive it given just the signature
                        res.addObject(serverPrivateECDHKeySig);
                        output.writeObject(res);

                        // User signature is verified, obtain user's ECDH public key and step 5 key agreement can now occur
                        // Generate Kab, shared secret between user and server
                        Kab = cs.generateSharedSecret(ECDHprivkey, userECDHPubKey);
//                        System.out.println("server side shared secret: " + cs.byteArrToHexStr(Kab));
                        // DEBUG: System.err.println("Shared secret: ", printHexBinary(Kab));
                        output.reset(); // TODO may cause issue
                        return true;
                    }
                }
            } else {
                System.out.println("Connection failed because envelope received from user isn't 'SignatureForHandshake'");
            }
        }  catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        return false;
    }

    private boolean tokenTimeValid(UserToken token) {
        int expirySecs = 300; // 5 minutes for now
        Instant t1 = token.getTimestamp();
        Instant t2 = Instant.now();
        return (t2.getEpochSecond() - t1.getEpochSecond()) <= expirySecs;
    }
}
