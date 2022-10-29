import org.bouncycastle.crypto.io.SignerOutputStream;

import java.io.File;
import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;

public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;

    public boolean connect(final String server, final int port) {
        System.out.println("attempting to connect");

        try {
          sock = new Socket(server, port);  
          output = new ObjectOutputStream(sock.getOutputStream());
          input = new ObjectInputStream(sock.getInputStream());

          // Check to see if the server's public key is cached or not, if not get the key sent by server
            // display it and ask user to verify it out-of-bound. If it is cached don't display, instead compare it
            // to see if group server sent the same public key as the one that is cached.
            // If it is, continue with connection else disconnect and display message saying that
            // the group server could not be verified.
          CryptoSec cs = new CryptoSec();
          Envelope pubKeyMsg = (Envelope)input.readObject();
          RSAPublicKey gsPubKey= (RSAPublicKey) pubKeyMsg.getObjContents().get(0);
          File serverKeys = new File("known_servers" + File.separator + pubKeyMsg.getMessage() +".public");

          if (serverKeys.exists()) {
              // Compare key sent by server to the cached one
              RSAPublicKey cachedGSPubKey = cs.readRSAPublicKey("known_servers" + File.separator + pubKeyMsg.getMessage() +".public");
              if(cs.byteArrToHexStr(gsPubKey.getEncoded()).equals(cs.byteArrToHexStr(cachedGSPubKey.getEncoded()))) {
                  System.out.println("The cached public key for this server matched the public key sent by " + server +
                          " at port " + port + ". Connecting...");
              } else {
                  disconnect();
                  System.out.println("Cached public key for server did not match the public key " + server + " at port "
                          + port + " provided. Disconnected. Type 'help' to see options.");
                  return false;
              }
          } else {
              System.out.println("No prior connection to this server found:");
              System.out.println("This group server's RSA public key in hex is:");
              System.out.println(cs.byteArrToHexStr(gsPubKey.getEncoded()));
              System.out.println("Verify with an admin that this matches the group server public key.");
              System.out.println("Enter 'y' to verify that the public key is valid and to continue and connect to the" +
                      " group server or 'n' to end the session:");
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

                      String pubKeyFilePath ="known_servers" + File.separator + pubKeyMsg.getMessage();
                      if (cs.writePubKey(pubKeyFilePath, gsPubKey)) {
                          System.out.println("Group Server's public key cached in " + pubKeyFilePath);
                      }
                      validInput = true;
                  } else if (userInput.equalsIgnoreCase("n")) {
                      disconnect();
                      System.out.println("Disconnected. Type 'help' to see options.");
                      return false;
                  } else {
                      System.out.println("Invalid input. Enter 'y' to verify that the public key is valid and connect" +
                              " to the group server or 'n' to end the session:");
                  }
              }
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

    public boolean isConnected() {
        if (sock == null || !sock.isConnected()) {
            return false;
        } else {
            return true;
        }
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);
                sock.close();
                sock = null;
            } catch(Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }
}
