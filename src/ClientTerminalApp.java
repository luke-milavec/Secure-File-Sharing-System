import java.util.Scanner;

import javax.sound.sampled.SourceDataLine;

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
                                
                            } else {
                                System.out.println("Token required to create username.");
                            }
                        } else {
                            System.out.println("Permission Denied.");
                        }
                    }
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
                            + "     help                                    Shows the list of valid commands." + newLine
                            + "     connect <-f or -g> <server> <port>      Connect to file or group server at port." + newLine
                            + "     disconnect                              Disconnects current connection to file or group server." + newLine
                            + "     group commands:                         Must be connected to group server." + newLine
                            + "         gettoken                            Gets a token for the user that is logged in." + newLine
                            + "         cgroup  <groupname>                 Create a group named group name." + newLine
                            + "         cuser  <username>                   Create a user named group name." + newLine
                            + "         dgroup <groupname>                  Delete group groupname." + newLine
                            + "         duser <username>                    Delete user username." + newLine
                            + "         adduser  <username>  <groupname>    Adds user username to group groupname." + newLine
                            + "         deleteuser  <username>  <groupname> Delete user username from group groupname." + newLine
                            + "     q                                       Closes the application."

        );
    }

    
    
    public static void main(String[] args) {
        new ClientTerminalApp();
        
    }
    
}
