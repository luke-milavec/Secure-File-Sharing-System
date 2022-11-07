import java.security.KeyPair;
import java.util.Scanner;
import java.io.File;
import java.util.List;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;




public class ClientTerminalApp {

    public UserList userList;
    public GroupList groupList;

    GroupClient gClient;
    FileClient fClient;
    UserToken token;
    String username;
    CryptoSec cs;


    ClientTerminalApp(){
        gClient = new GroupClient();
        fClient = new FileClient();
        token = null;
        cs = new CryptoSec();

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new AppShutDownListener(this));

        Scanner in = new Scanner(System.in);
        if (!login(in)) {
            // to do in next phase 
        }
        

        boolean exit = false;
        while (!exit) {
            String commandLine = in.nextLine();
            String[] command = commandLine.split(" ");
            switch (command[0]) {
                case "help":
                    showOptions();
                    break;
                case "relog": 
                    login(in);
                    break;
                case "connect":
                    // What sort of input validation should we add?
                    if (command.length != 4) {
                        System.out.println("Invalid parameters. Expected format: connect <-f or -g> <server> <port>");
                    } else if (!connect(command[1], command[2], command[3], username)) {
                            System.out.println("Connection failed: " + commandLine);
                    }
                     break;
                case "disconnect":
                    gClient.disconnect();
                    fClient.disconnect();
                    System.out.println("Disconnected from server");
                    break;
                case "gettoken": 
                    if(gClient.isConnected()) {
                        if(username != null) {
                            token = gClient.getToken(username);
                            if (token != null) {
                                System.out.println("Token Recieved");                                            
                            } else {
                                System.out.println("Request for token failed.");
                            }
                        }
                    } else {
                        System.out.println("Please connect to a group server first.");
                    }  
                    break;
                case "cuser":
                    if(gClient.isConnected()) {
                        if (username != null) {
                            // if (userList.getUserGroups(username).contains("ADMIN")) { // Security measure on client side as well
                                if (token != null) {
                                    if (command.length != 2) {
                                        System.out.println("Invalid format. Expected: cuser <username>");
                                    } else {
                                        if (!gClient.createUser(command[1], token)){
                                            System.out.println("Failed to create user.");
                                        } else {
                                            System.out.println("User " + command[1] + " created.");
                                            System.out.println("Please provide user with the group server's public " +
                                                    "key. The user will not be able to verify that they are connected" +
                                                    " to the legitimate group server otherwise.");
                                        }
                                    }               
                                } else {
                                    System.out.println("Token required to create username.");
                                }
                            // } else {
                            //     System.out.println("Permission Denied.");
                            // }
                        }
                    } else {
                        System.out.println("Connect to a group server first.");
                    }
                    break;
                case "duser": 
                    if (gClient.isConnected()) {
                        if (username != null) {
                            // if (userList.getUserGroups(username).contains("ADMIN")) { // Security measure on client side as well
                                if (token != null) {
                                    if (command.length != 2) {
                                        System.out.println("Invalid format. Expected: duser <username>");
                                    } else {
                                        if (!gClient.deleteUser(command[1], token)){
                                            System.out.println("Failed to delete user.");
                                        } else {
                                            System.out.println("User " + command[1] + " deleted.");
                                        }
                                    }               
                                } else {
                                    System.out.println("Token required to create new user. Please get a token first using gettoken");
                                }
                            // } else {
                            //     System.out.println("Permission Denied.");
                            // }
                        }
                    } else {
                        System.out.println("Connect to a group server first.");
                    }
                    
                    
                    break;
                case "cgroup":
                    if (gClient.isConnected()) {
                        if (token != null) {
                            if (command.length != 2) {
                                System.out.println("Invalid format. Expected: cgroup <groupname>");
                            } else {
                                if (!gClient.createGroup(command[1], token)){
                                    System.out.println("Failed to create group.");
                                } else {
                                    System.out.println("Group " + command[1] + " created.");
                                }
                            }               
                        } else {
                            System.out.println("Token required to create group. Please get a token first using gettoken");
                        }
                    }
                    else {
                        System.out.println("Connect to a group server first.");
                    }
                    break;
                case "dgroup":
                    if (gClient.isConnected()) {
                        if (token != null) {
                            if (command.length != 2) {
                                System.out.println("Invalid format. Expected: dgroup <groupname>");
                            } else {
                                if (!gClient.deleteGroup(command[1], token)){
                                    System.out.println("Failed to delete group.");
                                } else {
                                    System.out.println("Group " + command[1] + " deleted.");
                                }
                            }               
                        } else {
                            System.out.println("Token required to delete group. Please get a token first using gettoken");
                        }
                    }
                    else {
                        System.out.println("Connect to a group server first.");
                    }
                    break;
                case "adduser":
                    if (gClient.isConnected()) {
                        if (token != null) {
                            if (command.length != 3) {
                                System.out.println("Invalid format. Expected: adduser <username> <groupname>");
                            } else {
                                if (!gClient.addUserToGroup(command[1], command[2], token)){
                                    System.out.println("Failed to add " + command[1] + " to " + command[2] + ".");
                                } else {
                                    System.out.println(command[1] + " added to " + command[2] + ".");
                                }
                            }               
                        } else {
                            System.out.println("Valid token required to add user to group. Please get a token first using gettoken.");
                        }
                    }
                    else {
                        System.out.println("Connect to a group server first.");
                    }
                    break;
                case "ruser":
                    if (gClient.isConnected()) {
                        if (token != null) {
                            if (command.length != 3) {
                                System.out.println("Invalid format. Expected: ruser <username> <groupname>");
                            } else {
                                if (!gClient.deleteUserFromGroup(command[1], command[2], token)){
                                    System.out.println("Failed to delete " + command[1] + " from " + command[2] + ".");
                                } else {
                                    System.out.println(command[1] + " deleted from " + command[2] + ".");
                                }
                            }               
                        } else {
                            System.out.println("Valid token required to delete user from group. Please get a token first using gettoken.");
                        }
                    }
                    else {
                        System.out.println("Connect to a group server first.");
                    }
                    break;
                case "listmembers":
                    if (gClient.isConnected()) {
                        if (token != null) {
                            if (command.length != 2) {
                                System.out.println("Invalid format. Expected: listmembers <groupname>");
                            } else {
                                List<String> members = gClient.listMembers(command[1], token);
                                if (members != null) {
                                    for (String member : members) {
                                        System.out.println(member);
                                    }
                                } else {
                                    System.out.println("Failed to get list of members.");
                                }
                            }               
                        } else {
                            System.out.println("Valid token required to list group members. Please get a token first using gettoken.");
                        }
                    } else {
                        System.out.println("Connect to a group server first.");
                    }
                    break;
                case "download":
                    if (fClient.isConnected()) { 
                        if (token != null) {
                            if(command.length != 3) {
                                System.out.println("Invalid format. Expected: download <sourcefilename> <destfilename>");
                            } else {
                                    boolean isdownloaded = fClient.download(command[1], command[2], token);
                                    if(!isdownloaded) {
                                        System.out.println("Failed to download file.");
                                    }

                            }
                        } else {
                            System.out.println("Valid token required to download file. Please get a token first using gettoken.");
                        }
                    } else {
                        System.out.println("Connect to a file server first.");
                    }     
                    break;
                case "upload":
                    if (fClient.isConnected()) { 
                        if (token != null) {
                            if(command.length != 4) {
                                System.out.println("Invalid format. Expected: upload <sourcefilename> <destfilename> <group>");
                            } else {
                                    File f = new File(command[1]);
                                    if (!f.exists()) {
                                        System.out.println("File " + command[1] + " does not exist.");
                                    } else {
                                        boolean isuploaded = fClient.upload(command[1], command[2], command[3], token);
                                        if(!isuploaded) {
                                            System.out.println("Failed to upload file.");
                                        }
                                    }
                            }
                        } else {
                            System.out.println("Valid token required to upload file to group. Please get a token first using gettoken.");
                        }
                    } else {
                        System.out.println("Connect to a file server first.");
                    }     
                    break;
                case "listfiles":
                    if (fClient.isConnected()) { 
                        if (token != null) {
                            List<String> files = fClient.listFiles(token);
                            System.out.println("There are " + files.size() + " files.");
                                    for (String file : files) {
                                        System.out.println(file);
                                    }
                        } else {
                            System.out.println("Valid token required to list files. Please get a token first using gettoken.");
                        }
                    } else {
                        System.out.println("Connect to a file server first.");
                    }     
                    break;
                case "delete":
                    if (fClient.isConnected()) { 
                        if (token != null) {
                            if(command.length != 2) {
                                System.out.println("Invalid format. Expected: delete <filename>");
                            } else {
                                boolean isdeleted = fClient.delete(command[1], token);
                                if(!isdeleted) {
                                    System.out.println("Failed to delete file.");
                                }
                            }
                        } else {
                            System.out.println("Valid token required to delete file. Please get a token first using gettoken.");
                        }
                    } else {
                        System.out.println("Connect to a file server first.");
                    }     
                    break;
                case "q":
                    exit = true;
                    break;
                
                default:
                    System.out.println("Invalid command, please type help to see valid commands.");
            }
        }
        in.close();
    }

    public boolean login(Scanner in) {

        // In case of relogging, close out previous session. 
        token = null;
        username = null;
        if(gClient != null && gClient.isConnected()){
            gClient.disconnect();
            gClient = null;
        }
        if(fClient != null && fClient.isConnected()){
            fClient.disconnect();
            fClient = null;
        }

        System.out.println("Enter username to login: ");
        username = in.nextLine();
        File pubKFile = new File(username + ".public");
        File privKFile = new File(username + ".private");
        // If user accidentally deletes key files should we check for that and let them regenerate them?
        if (!pubKFile.exists() || !privKFile.exists()) {
            System.out.println("No RSA Key Pair exists yet for " + username + " or it was lost." +
                    " Generating RSA Key Pair..." + System.lineSeparator() +
                     "If you encounter trouble getting a token, an Admin may not" +
                    " have created a user with this username yet." + System.lineSeparator() +
                    "Please contact an admin to setup a user" +
                    " under this username if you encounter this issue." + System.lineSeparator() +
                    "If the Admin has already created a user with this" +
                    " username there should be no trouble using the system." + System.lineSeparator());


            KeyPair rsaKeyPair = cs.genRSAKeyPair();
            if(cs.writeKeyPair(username, rsaKeyPair)) {
                System.out.println("An RSA Key Pair has been generated and stored in files '" + username + ".public'"
                        + " and '" + username + ".private' in the current directory." + System.lineSeparator() +
                        "Please do not delete them if you wish to continue using this account."
                        + System.lineSeparator());
            } else {
                System.out.println("Sorry error generating keys, please try again");
                System.exit(-1);
            }

        }
        gClient = new GroupClient();
        fClient = new FileClient();
        System.out.println("Type 'help' to see options:");
        return true; // For now there are no checks 
    }

    public boolean connect(String serverType, String serverName, String port, String username) {
        if (serverType.equals("-g")) {
            if (gClient.connect(serverName, Integer.parseInt(port), username)) {
                return true;
            }
        } else if (serverType.equals("-f")) {
            if (fClient.connect(serverName, Integer.parseInt(port), username)) {
                return true;
            }
        }
        else {
            System.out.println("Invalid server type. Correct options were -g or -f");
        }
        return false;
    }

    public void showOptions() {
        String newLine = System.lineSeparator();
        System.out.println("Options: " + newLine
                            + "     help                                                    Shows the list of valid commands." + newLine
                            + "     relog                                                   Re-login to app, perhaps to change accounts." + newLine
                            + "     connect <-f or -g> <server> <port>                      Connect to a file or group server at the port specified." + newLine
                            + "     disconnect                                              Disconnect current connection to file and/or group server." + newLine
                            + "     group commands:                                         Must be connected to group server. Commands other than gettoken require valid token." + newLine
                            + "         gettoken                                            Fetch a token for the user that is logged in." + newLine
                            + "         cgroup <groupname>                                  Create a group named <groupname>." + newLine
                            + "         cuser <username>                                    Create a user named <username>." + newLine
                            + "         dgroup <groupname>                                  Delete the group specified by <groupname>." + newLine
                            + "         duser <username>                                    Delete the user specified by <username>." + newLine
                            + "         adduser <username> <groupname>                      Add user <username> to group <groupname>." + newLine
                            + "         ruser <username> <groupname>                        Delete user <username> from group <groupname>." + newLine
                            + "         listmembers <groupname>                             List all members of <groupname>." + newLine
                            + "     file commands:                                          Must be connected to a file server. Commands require valid tokens" + newLine
                            + "         download <sourceFile> <destFile>                    Download <sourceFile> from server and saves it as <destFile>." + newLine
                            + "         upload   <srcFile> <destFile> <group>               Upload <sourceFile> to file server as a file of <group>." + newLine
                            + "         listfiles                                           List all files that the logged in user has access to via their token." + newLine
                            + "         delete <filename>                                   Delete file <filename> from server." + newLine
                            + "     q                                                       Close the application."
        );
    }


    
    
    public static void main(String[] args) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        new ClientTerminalApp();
        
    }
    
}

//This thread saves the user list AND group list (added)
class AppShutDownListener extends Thread {
    public ClientTerminalApp my_app;

    public AppShutDownListener (ClientTerminalApp _app) {
        my_app = _app;
    }

    public void run() {
        System.out.println("Shutting down app");
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_app.userList);

            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
            outStream.writeObject(my_app.groupList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}
