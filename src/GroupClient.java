/* Implements the GroupClient Interface */
import java.util.ArrayList;
import java.util.List;


public class GroupClient extends Client implements GroupClientInterface {

    CryptoSec cs;

    public GroupClient() {
        cs = new CryptoSec();
    }

    public Message getToken(String username) {
        try {
            UserToken token = null;
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("GET");
            message.addObject(username); //Add user name string

            Message encryptedMsg = cs.encryptEnvelope(message, Kab);
//            System.out.println(cs.byteArrToHexStr(encryptedMsg.enc));
//            System.out.println(cs.byteArrToHexStr(encryptedMsg.hmac));
            output.writeObject(encryptedMsg);
//            output.writeObject(message);

            //Get the response from the server
            // TODO uncomment following 2 lines
            encryptedMsg = (Message) input.readObject();
            response = cs.decryptEnvelopeMessage(encryptedMsg, Kab);
//            response = (Envelope)input.readObject();

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                
                ArrayList<Object> temp = null;
                temp = response.getObjContents();
                

                if(temp.size() == 1) {
//                    token = (UserToken)temp.get(0);
//                    System.out.println(cs.byteArrToHexStr(gsPubKey.getEncoded()));
                    
                    return (Message) temp.get(0);
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); //Add user name string
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); //Add username
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); //Add the group name string
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);


            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); //Add group name string
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group); //Add group name string
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);

            //If server indicates success, return the member list
            if(response.getMessage().equals("OK")) {
                return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;

            // Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
//            Message enTok = cs.encryptToken(token, Kab);
//            message.addObject(enTok); //Add the requester's token
            message.addObject(token);
            Message encryptedMessage = cs.encryptEnvelope(message, Kab); // encrypt envelope
            output.writeObject(encryptedMessage);

            response = cs.decryptEnvelopeMessage((Message) input.readObject(), Kab);
            //If server indicates success, return true
            return response.getMessage().equals("OK");
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

}
