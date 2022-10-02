import java.util.Scanner;
import java.util.List;



public class ClientTerminalApp {

    GroupClient gClient;
    FileClient fClient;
    UserToken token;
    String username;


    ClientTerminalApp(){
        gClient = new GroupClient();
        fClient = new FileClient();
        token = null;

        Scanner in = new Scanner(System.in);
        if (!login(in)) {
            // TODO
        }
        showOptions();

        boolean exit = false;
        while (!exit) {
            String commandLine = in.nextLine();
            String[] command = commandLine.split(" ");
            switch (command[0]) {
                case "help":
                    showOptions();
                    break;
                case "connect":
                    // What sort of input validation should we add?
                    if (command.length != 4) {
                        System.out.println("Invalid parameters. Expected format: connect <-f or -g> <server> <port>");
                    } else if (!connect(command[1], command[2], command[3])) {
                        System.out.println("Connection failed: " + commandLine);
                    }
                     break;
                case "disconnect":
                    gClient.disconnect();
                    fClient.disconnect();
                    System.out.println("Disconnected from server");
                    break;
                case "gettoken": 
                // BUG 1: server sees ADMIN username and it creates token fine but first gettoken
                // request is recieved as a FAIL on client side, second gettoken request works fine
                    if(username != null && gClient.isConnected()) {
                        token = gClient.getToken(username);
                        if (token != null) {
                            System.out.println("Token Recieved");            
                            // for testing
                            System.out.println("issuer: " + token.getIssuer() + " subject: " + token.getSubject()
                            + " groups: " + token.getGroups());
                            
                        } else {
                            System.out.println("Request for token failed.");
                        }
                    }
                    break;
                case "cuser":
                    if (username != null && gClient.isConnected()) {
                        if (username.equals("ADMIN")) { // Security measure on client side as well
                            if (token != null) {
                                if (command.length != 2) {
                                    System.out.println("Invalid format. Expected: cuser <username>");
                                } else {
                                    if (!gClient.createUser(command[1], token)){
                                        System.out.println("Failed to create user.");
                                    } else {
                                        System.out.println("User " + command[1] + " created.");
                                    }
                                }               
                            } else {
                                System.out.println("Token required to create username.");
                            }
                        } else {
                            System.out.println("Permission Denied.");
                        }
                    }
                    break;
                case "duser": 
                    if (username != null && gClient.isConnected()) {
                        if (username.equals("ADMIN")) { // Security measure on client side as well
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
                                System.out.println("Token required to create username. Please get a token first using gettoken");
                            }
                        } else {
                            System.out.println("Permission Denied.");
                        }
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
                    // TODO
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
                case "deleteuser":
                    // TODO
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
        System.out.println("Enter username to login: ");
        username = in.nextLine();
        return true; // For now there are no checks 
    }

    public boolean connect(String serverType, String serverName, String port) {
        if (serverType.equals("-g")) {
            if (gClient.connect(serverName, Integer.parseInt(port))) {
                return true;
            }
        } else if (serverType.equals("-f")) {
            if (fClient.connect(serverName, Integer.parseInt(port))) {
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
                            + "     help                                        Shows the list of valid commands." + newLine
                            + "     connect <-f or -g> <server> <port>          Connect to file or group server at port." + newLine
                            + "     disconnect                                  Disconnects current connection to file or group server." + newLine
                            + "     group commands:                             Must be connected to group server. Commands other than gettoken require valid token." + newLine
                            + "         gettoken                                Gets a token for the user that is logged in." + newLine
                            + "         cgroup <groupname>                      Create a group named group name." + newLine
                            + "         cuser <username>                        Create a user named group name." + newLine
                            + "         dgroup <groupname>                      Delete group groupname." + newLine
                            + "         duser <username>                        Delete user username." + newLine
                            + "         adduser <username> <groupname>          Adds user username to group groupname." + newLine
                            + "         deleteuser <username> <groupname>       Delete user username from group groupname." + newLine
                            + "         listmembers <groupname>                 Lists all members of groupname." + newLine
                            + "     q                                           Closes the application."

        );
    }

    
    
    public static void main(String[] args) {
        new ClientTerminalApp();
        
    }
    
}
