/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;



public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
    }

    public void run() {
        boolean proceed = true;

        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            do {
                output.reset();
                Envelope message = (Envelope)input.readObject();
                System.out.println("Request received: " + message.getMessage());
                Envelope response;

                if(message.getMessage().equals("GET")) { //Client wants a token
                    String username = (String)message.getObjContents().get(0); //Get the username
                    
                    // TODO remove following line, added for testing
                    System.out.println("username: " + username + " requested a token.");
                    if(username == null) {
                        response = new Envelope("FAIL");
                        response.addObject(null);
                        output.writeObject(response);
                    } else {
                        UserToken yourToken = createToken(username); //Create a token
                        // TODO remove debug prints
                        if(yourToken != null) {
                            System.out.println("token not null");
                            System.out.println("issuer: " + yourToken.getIssuer() + " subject: " + yourToken.getSubject()
                            + "  groups: " + yourToken.getGroups());
                        }
                        else
                        {
                            System.out.println("token is null");
                        }
                        //Respond to the client. On error, the client will receive a null token
                        response = new Envelope("OK");
                        response.addObject(yourToken);
                        output.writeObject(response);
                    }
                } else if(message.getMessage().equals("CUSER")) { //Client wants to create a user
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String username = (String)message.getObjContents().get(0); //Extract the username
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                                if(createUser(username, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                        }
                    }

                    output.writeObject(response);
                } else if(message.getMessage().equals("DUSER")) { //Client wants to delete a user

                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String username = (String)message.getObjContents().get(0); //Extract the username
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                                if(deleteUser(username, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                        }
                    }

                    output.writeObject(response);
                } else if(message.getMessage().equals("CGROUP")) { //Client wants to create a group
                    /* TODO:  Write this handler */
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL"); //default fail
                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String groupname = (String)message.getObjContents().get(0); //Extract the groupname
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                                if(createGroup(groupname, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                        }
                    }
                    output.writeObject(response);
                } else if(message.getMessage().equals("DGROUP")) { //Client wants to delete a group
                    /* TODO:  Write this handler */
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL"); // default fail
                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String groupname = (String)message.getObjContents().get(0); //Extract the groupname
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                
                                if(deleteGroup(groupname, yourToken)) {
                                    response = new Envelope("OK"); //Success
                                }
                            }
                        }
                    }
                    output.writeObject(response);
                } else if(message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
                    response = new Envelope("FAIL");
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL"); // default fail
                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String groupname = (String)message.getObjContents().get(0); //Extract the groupname
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                
                                ArrayList<String> members = listMembers(groupname, yourToken);

                                //response = new Envelope(listMembers(groupname, yourToken));
                                response = new Envelope("OK");
                                response.addObject(members);
                                
                            }
                        }
                    }
                    output.writeObject(response);
                } else if(message.getMessage().equals("AUSERTOGROUP")) { //Client wants to add user to a group
                    /* TODO:  Write this handler */
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL"); // default fail
                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                if(message.getObjContents().get(2) != null){
                                    String username = (String)message.getObjContents().get(0);
                                    String groupname = (String)message.getObjContents().get(1); 
                                    UserToken yourToken = (UserToken)message.getObjContents().get(2);
                                    
                                    if(addUserGroup(username,groupname, yourToken)) {
                                        response = new Envelope("OK"); //Success
                                    }
                                }  
                            }
                        }
                    }
                output.writeObject(response);
                } else if(message.getMessage().equals("RUSERFROMGROUP")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL"); // default fail
                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                if(message.getObjContents().get(2) != null){
                                    String username = (String)message.getObjContents().get(0);
                                    String groupname = (String)message.getObjContents().get(1); 
                                    UserToken yourToken = (UserToken)message.getObjContents().get(2);
                                    
                                    if(removeUserGroup(username,groupname, yourToken)) {
                                        response = new Envelope("OK"); //Success
                                    }
                                }  
                            }
                        }
                    }
                output.writeObject(response);
                } else if(message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                } else {
                    response = new Envelope("FAIL"); //Server does not understand client request
                    output.writeObject(response);
                }
            } while(proceed);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    //Method to create tokens
    private UserToken createToken(String username) {
        
        //Check that user exists
        if(my_gs.userList.checkUser(username)) {
            //Issue a new token with server's name, user's name, and user's groups
            UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
            return yourToken;
        } else {
    
            return null;
        }
    }


    //Method to create a user
    private boolean createUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Check if requester exists
        if(my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if(temp.contains("ADMIN")) {
                //Does user already exist?
                if(my_gs.userList.checkUser(username)) {
                    System.out.println("Debug group thread createUser(): user " + username + " already exists");
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username);
                    System.out.println("Debug group thread createUser(): user " + username + " added:");
                    return true;
                }
            } else {
                return false; //requester not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    //Method to delete a user
    private boolean deleteUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administer
            if(temp.contains("ADMIN")) {
                //Does user exist?
                if(my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    //If user is the owner, removeMember will automatically delete group!
                    for(int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    return true;
                } else {
                    return false; //User does not exist

                }
            } else {
                return false; //requester is not an administer
            }
        } else {
            return false; //requester does not exist
        }
    }

    private boolean createGroup(String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            if(!my_gs.groupList.checkGroup(groupname)) { // if group doesn't already exist
                    my_gs.groupList.addGroup(requester, groupname); // add group to grouplist with requester as owner
                    my_gs.userList.addGroup(requester, groupname); // Add group to user's list of groups they belong to
                    my_gs.userList.addOwnership(requester, groupname); // Add group to user's list of groups they own
                    return true;
                } else {
                    return false; // Group already exists
                }
            } else {
                return false; //requester does not exist
        }
    }
    
    // Stub
    private boolean deleteGroup(String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            if(my_gs.groupList.checkGroup(groupname)) { // if group exists
                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) { // if requester is the group owner
                        ArrayList<String> members = my_gs.groupList.getGroupMembers(groupname); // List of all group members
                        // Delete the group from every member's list of groups they belong to
                        for (int i = 0; i < members.size(); i++) {
                            my_gs.userList.removeGroup(members.get(i), groupname);
                        }
                        // delete from owner's ownership list
                        my_gs.userList.removeOwnership(requester, groupname);
                        
                        // delete from grouplist
                        my_gs.groupList.deleteGroup(groupname);
                        return true;
                    }
                    else {
                        return false; // Non-owner attempting to delete group
                    }
                } else {
                    return false; // Group doesn't exist, nothing to delete
                }
            } else {
                return false; //requester does not exist
        }
    }

    private ArrayList<String> listMembers(String groupname, UserToken yourToken){
        String requester = yourToken.getSubject();
        // String re = groupname+":\n";
        ArrayList<String> re = null;

        if(my_gs.userList.checkUser(requester)) {
            if(my_gs.groupList.checkGroup(groupname)){
                if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) {
                    System.err.println("request for list members in groupthread listMembers(): requester " + requester
                    + " groupname: " + groupname + " my_gs.groupList.getGroupOwner: " + my_gs.groupList.getGroupOwner(groupname));

                    
                    ArrayList<String> members = my_gs.groupList.getGroupMembers(groupname); // List of all group members
                    System.err.println("in listMembers(): " + members.toString());
                    return members;
                    // I think this approach might be incorrect because groupclient is expecting a List<String>
                        // for (int i = 0; i < members.size(); i++) {
                        //     re += members.get(i)+"\n";
                        // }
                }
            }
        }
        return re;
    }

    private boolean addUserGroup(String username,String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();
        System.err.println(" Debug groupthread addUserGroup(): requester: " + requester + "; groupname: " + groupname);
        System.err.println(" Debug groupthread addUserGroup(): groupowner: " + my_gs.groupList.getGroupOwner(groupname));
        System.err.println(" Debug groupthread addUserGroup(): checkgroup: " + my_gs.groupList.checkGroup(groupname));
        System.err.println(" Debug groupthread UserGroup(): checkuser username: " + username + " checkuser: " + my_gs.userList.checkUser(username));
        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            if(my_gs.groupList.checkGroup(groupname)) { // if group exists
                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) { 
                        if(my_gs.userList.checkUser(username) && !my_gs.groupList.getGroupMembers(groupname).contains(username)){
                            my_gs.groupList.addMember(username, groupname); 
                            my_gs.userList.addGroup(username, groupname); 
                            System.err.println("Debug groupthread addUserGroup(): checkuser checkgroup and groupowner match passes");
                            
                            return true;
                        } else {
                            return false; 
                        }
                    } else {
                        return false; 
                    }
                } else {
                    return false; 
                }
            } else {
                return false; 
        }
    }

    private boolean removeUserGroup(String username,String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            if(my_gs.groupList.checkGroup(groupname)) { // if group exists
                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) { 
                        if(my_gs.userList.checkUser(username)){
                            ArrayList<String> members = my_gs.groupList.getGroupMembers(groupname); // List of all group members
                            for (int i = 0; i < members.size(); i++) {
                                if(members.get(i).equals(username)){
                                    my_gs.groupList.removeMember(username, groupname);
                                    my_gs.userList.removeGroup(username, groupname);
                                    return true;
                                }
                            }
                            return false; //nout found
                        } else {
                            return false; 
                        }
                        
                    } else {
                        return false; 
                    }
                } else {
                    return false; 
                }
            } else {
                return false; 
        }
    }
}
