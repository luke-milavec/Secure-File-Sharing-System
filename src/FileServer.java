/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Scanner;

public class FileServer extends Server {

    public static FileList fileList;
    Scanner console = new Scanner(System.in);

    public FileServer(int _port) {
        super(_port, "omega");
    }

    public void start() {
        String fileFile = "FileList.bin";
        ObjectInputStream fileStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        Thread catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList = (FileList)fileStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("FileList Does Not Exist. Creating FileList...");

            fileList = new FileList();

        } catch(IOException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        System.out.print("Enter the name of the file server to start or a new name to setup a new file server: ");
        String fsName = console.next();
        File pubKeyFile = new File(fsName + ".public");
        if(!pubKeyFile.exists()) {
            // Generate RSA keypair for the user and another for the group server
            CryptoSec cs = new CryptoSec();
            KeyPair fsKeyPair = cs.genRSAKeyPair();
            cs.writeKeyPair(fsName, fsKeyPair);
            System.out.println("An RSA Key Pair has been generated for " + fsName +
                    " and stored in files '" + fsName +
                    ".public' and '" + fsName + ".private' in the current directory.");
            System.out.println();

            // Write a hex version of the group server's public key to a new file, meant to be used for verification
            // purposes
            String pubHexString = cs.byteArrToHexStr(fsKeyPair.getPublic().getEncoded());
            if (cs.writeStrToFile(fsName + "_pub_key_hex", pubHexString)) {
                System.out.println("A hex version of the File Server, " + fsName + "'s public key has been written to"
                        + fsName + "_pub_key_hex.txt in the current directory.");
                System.out.println("This is meant to be given to trusted new users out-of-band as needed so they can" +
                        " verify they are connecting to the right file server.");
            } else {
                System.out.println("There was an error writing hex version of the file server" +
                        ", " + fsName + "'s public key to file.");
            }
            System.out.println();
        } else {
            System.out.println("Found File Server, " + fsName + "'s RSA KeyPair");
        }


        File file = new File("shared_files");
        if (file.mkdir()) {
            System.out.println("Created new shared_files directory");

        } else if (file.exists()) {
            System.out.println("Found shared_files directory");
        } else {
            System.out.println("Error creating shared_files directory");
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            Thread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new FileThread(sock, fsName);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        try {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSaveFS extends Thread {
    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }
            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
