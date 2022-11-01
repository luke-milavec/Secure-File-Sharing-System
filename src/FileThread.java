/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

            // conduct Handshake A
            if (!handshake(input, output)) {
                System.out.println("Error connecting, file server could not be verified.");
                Envelope errMsg = new Envelope("FAIL");
                errMsg.addObject(null);
                output.writeObject(errMsg);
            }

            do {
                Envelope e = (Envelope)input.readObject();
                System.out.println("Request received: " + e.getMessage());
                // Handler to list files that this user is allowed to see
                if(e.getMessage().equals("LFILES")) {
                    if(e.getObjContents().size() < 1) {  // no token sent
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else if (e.getObjContents().get(0) == null){ // if the token is null
                        response = new Envelope("FAIL-BADTOKEN");
                    } else {
                        UserToken token = (UserToken) e.getObjContents().get(0); // extract token
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
                    }
                    output.writeObject(response);
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
                            UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

                            if (FileServer.fileList.checkFile(remotePath)) {
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
                                output.writeObject(response);

                                e = (Envelope)input.readObject();
                                while (e.getMessage().compareTo("CHUNK")==0) {
                                    fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
                                    response = new Envelope("READY"); //Success
                                    output.writeObject(response);
                                    e = (Envelope)input.readObject();
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

                    output.writeObject(response);
                } else if (e.getMessage().compareTo("DOWNLOADF")==0) {

                    String remotePath = (String)e.getObjContents().get(0);
                    Token t = (Token)e.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                    if (sf == null) {
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        e = new Envelope("ERROR_FILEMISSING");
                        output.writeObject(e);

                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        e = new Envelope("ERROR_PERMISSION");
                        output.writeObject(e);
                    } else {

                        try {
                            File f = new File("shared_files/_"+remotePath.replace('/', '_'));
                            if (!f.exists()) {
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                e = new Envelope("ERROR_NOTONDISK");
                                output.writeObject(e);

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
                                    
                                    output.writeObject(e);

                                    e = (Envelope)input.readObject();


                                } while (fis.available()>0);

                                //If server indicates success, return the member list
                                if(e.getMessage().compareTo("DOWNLOADF")==0) {

                                    e = new Envelope("EOF");
                                    output.writeObject(e);

                                    e = (Envelope)input.readObject();
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
                    Token t = (Token)e.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                    if (sf == null) {
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
                    output.writeObject(e);

                } else if(e.getMessage().equals("DISCONNECT")) {
                    socket.close();
                    proceed = false;
                }
            } while(proceed);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private boolean handshake(final ObjectInputStream input, final ObjectOutputStream output) {
        try {
            System.out.println(fsName);
            // Send over group server's Public Key as RSAPublicKey so that user can verify it
            RSAPublicKey fsPubKey = cs.readRSAPublicKey(fsName + ".public");
            Envelope resKey = new Envelope("fs_pub_key");
            resKey.addObject(fsPubKey);
            output.writeObject(resKey);

            // Handshake
            Envelope signedRSA = (Envelope)input.readObject(); // user sent ECDH signed key
            if(signedRSA.getMessage().equals("SignatureForHandshake")) {
                RSAPublicKey userRSApublickey = (RSAPublicKey) signedRSA.getObjContents().get(1);
                byte[] userPrivateECKeySig = (byte[]) signedRSA.getObjContents().get(2);

                Envelope res;
                // Checks for if any are null
                if(userRSApublickey == null || userPrivateECKeySig == null) {
                    res = new Envelope("FAIL");
                    res.addObject(null);
                    output.writeObject(res);
                } else {
                    // TODO need to verify whether user sent signature was really signed by the user before doing:

                    // Generate ECDH keypair
                    KeyPair ECDHkeys = cs.genECDHKeyPair();
                    PublicKey ECDHpubkey = ECDHkeys.getPublic();
                    PrivateKey ECDHprivkey = ECDHkeys.getPrivate();

                    // Sign ECDH public key with RSA private key of file server
                    RSAPublicKey serverRSApublickey = cs.readRSAPublicKey(fsName + ".public");
                    RSAPrivateKey serverRSAprivatekey = cs.readRSAPrivateKey(fsName);
                    byte[] serverPrivateECDHKeySig = cs.rsaSign(serverRSAprivatekey, ECDHpubkey.getEncoded());

                    // Send back to user
                    res = new Envelope("SignatureForHandshake");
                    res.addObject(serverPrivateECDHKeySig);
                    output.writeObject(res);


                    return true; // TODO once handshake implemented make sure this goes to correct place
                }
            } else {
                System.out.println("Connection failed cause envelope received from user isn't 'SignatureForHandshake'");
            }
//            output.reset(); // TODO test if this causes issues
        }  catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        return false;
    }
}
