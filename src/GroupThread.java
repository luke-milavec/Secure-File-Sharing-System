/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Thread;
import java.net.Socket;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.security.*;



public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;

    private byte[] Kab;

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
    }

    public void run() {
        boolean proceed = true;

        try {
            CryptoSec cs = new CryptoSec();
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            // Send over group server's Public Key as RSAPublicKey so that user can verify it
            RSAPublicKey gsPubKey = cs.readRSAPublicKey("gs");
            Envelope resKey = new Envelope("gs_pub_key");
            resKey.addObject(gsPubKey);
            output.writeObject(resKey);

            Envelope signedRSA = (Envelope)input.readObject();

            // Handshake
            if(signedRSA.getMessage().equals("SignatureForHandshake")) {
                String username = (String) signedRSA.getObjContents().get(0);
                RSAPublicKey userRSApublickey = (RSAPublicKey) signedRSA.getObjContents().get(1);
                PublicKey userECDHPubKey = (PublicKey) signedRSA.getObjContents().get(2);
                byte[] UserECDHpubKeySigned = (byte[]) signedRSA.getObjContents().get(3);

                // Initialize response envelope
                Envelope res;
                // Checks for if any contents are null
                if(username == null || userRSApublickey == null || userECDHPubKey == null || UserECDHpubKeySigned == null) {

                    res = new Envelope("FAIL");
                    res.addObject(null);
                    output.writeObject(res);
                } else {

                    // Verifying signature      ?? is this correct way to do it ?? 
                    // docs don't mention they need public key sent in this method because of initVerify()
                    Signature verifySig = Signature.getInstance("SHA256withRSA", "BC");
                    verifySig.initVerify(userRSApublickey);
                    verifySig.update(userECDHPubKey.getEncoded());
                    // If false, this user did NOT sign the message contents
                    if(!verifySig.verify(UserECDHpubKeySigned)) {

                        res = new Envelope("FAIL");
                        res.addObject(null);
                        output.writeObject(res);
                    } else {
                        // Generate ECDH keypair
                        KeyPair ECDHkeys = cs.genECDHKeyPair();
                        PublicKey ECDHpubkey = ECDHkeys.getPublic();
                        PrivateKey ECDHprivkey = ECDHkeys.getPrivate();

                        // Sign ECDH public key with RSA private key of group server
                        RSAPublicKey serverRSApublickey = cs.readRSAPublicKey("gs");
                        RSAPrivateKey serverRSAprivatekey = cs.readRSAPrivateKey("gs");
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
                    }

                }
            } else {
                System.out.println("Connection failed cause envelope received from user isn't 'SignatureForHandshake'");
            }

            do {
                output.reset();
                Message msg = (Message) input.readObject();
//                Envelope message = (Envelope)input.readObject();
//                System.out.println(cs.byteArrToHexStr(msg.enc));
//                System.out.println(cs.byteArrToHexStr(msg.hmac));
               Envelope message = cs.decryptEnvelopeMessage(msg, Kab);
               if(message != null) {
                   System.out.println("Request received: " + message.getMessage());
                   Envelope response;

                   if(message.getMessage().equals("GET")) { //Client wants a token
                       String username = (String)message.getObjContents().get(0); //Get the username
                       System.out.println(username + " requested a token");
                       if(username == null) {
                           response = new Envelope("FAIL");
                           response.addObject(null);
                           output.writeObject(cs.encryptEnvelope(response, Kab));
                       } else {
                           UserToken yourToken = createToken(username); //Create a token
//                           System.out.println("server token bytes:");
//                           System.out.println(cs.byteArrToHexStr(cs.serializeObject(yourToken)));
                           Message enTok = cs.encryptToken(yourToken, username, Kab);

                           //Respond to the client. On error, the client will receive a null token
                           response = new Envelope("OK");
//                           response.addObject(yourToken);
                           response.addObject(enTok);
//                           output.writeObject(response);
                           output.writeObject(cs.encryptEnvelope(response, Kab));
                       }
                   } else if(message.getMessage().equals("CUSER")) { //Client wants to create a user
                       if(message.getObjContents().size() < 2) {
                           System.out.println("In here");
                           response = new Envelope("FAIL");
                       } else {
                           response = new Envelope("FAIL");
                           if(message.getObjContents().get(0) != null) {
                               if(message.getObjContents().get(1) != null) {
                                   String username = (String)message.getObjContents().get(0); //Extract the username
//                                   UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                     UserToken yourToken = cs.decryptTokenMessage((Message) message.getObjContents().get(1), Kab, gsPubKey);
                                   if(createUser(username, yourToken)) {
                                       response = new Envelope("OK"); //Success
                                   }
                               }
                           }
                       }

                       output.writeObject(cs.encryptEnvelope(response, Kab));
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
               } else {
                   System.out.println("Failed since message from client was null after decryption");
                   Message response = cs.encryptEnvelope(new Envelope("FAIL"), Kab);
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
        System.out.println("in create user");
        //Check if requester exists
        if(my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if(temp.contains("ADMIN")) {
                //Does user already exist?
                if(my_gs.userList.checkUser(username)) {
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username);
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
                if(username.equals("ADMIN")){
                    return false;
                }
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
        ArrayList<String> members = null;

        if(my_gs.userList.checkUser(requester)) {
            if(my_gs.groupList.checkGroup(groupname)){
                if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) {
                    members = my_gs.groupList.getGroupMembers(groupname); // List of all group members
                    return members;
                }
            }
        }
        return members;
    }

    private boolean addUserGroup(String username,String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();
        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            if(my_gs.groupList.checkGroup(groupname)) { // if group exists
                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) { 
                        if(my_gs.userList.checkUser(username) && !my_gs.groupList.getGroupMembers(groupname).contains(username)){
                            my_gs.groupList.addMember(username, groupname); 
                            my_gs.userList.addGroup(username, groupname); 
                            
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
                            return false; //not found
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
