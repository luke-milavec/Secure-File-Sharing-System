import java.util.Scanner;

public class ClientTerminalApp {

    GroupClient gClient;
    FileClient fClient;

    ClientTerminalApp(){
        gClient = new GroupClient();
        fClient = new FileClient();

        Scanner in = new Scanner(System.in);
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
                    if(!connect(command[1], command[2], command[3])) {
                        System.out.println("Connection failed: " + commandLine);
                    }
                     break;
                case "disconnect":
                     gClient.disconnect();
                     fClient.disconnect();
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

    public boolean connect(String serverType, String serverName, String port) {
        if (serverType.equals("-g")) {
            if (gClient.connect(serverName, Integer.parseInt(port))) {
                return true;
            }
            else {
                System.out.println("ouchee could not connect to group server");
            }

        } else if (serverType.equals("-f")) {
            System.out.println("TODO");
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
                            + "     connect [-f or -g] [server] [port]      Connect to file or group server at port." + newLine
                            + "     disconnect                              Disconnects current connection to file or group server." + newLine
                            + "     group commands:                         Must be connected to group server." + newLine
                            + "         token                               Gets a token based on the user login info??." + newLine
                            + "         cgroup  <groupname>                 Create a group named group name. Must be Admin" + newLine
                            + "         cuser  <username>                   Create a user named group name. Must be ADMIN" + newLine
                            + "         dgroup <groupname>                  Delete group groupname." + newLine
                            + "         duser <username>                    Delete user username." + newLine
                            + "         addUser  <username>  <groupname>    Adds user username to group groupname." + newLine
                            + "         deleteUser  <username>  <groupname> Delete user username from group groupname." + newLine
                            + "     q                                       Closes the application."

        );
    }

    
    
    public static void main(String[] args) {
        new ClientTerminalApp();
        
    }
    
}
