/* This list represents the groups on the server */
import java.util.ArrayList;
import java.util.Hashtable;

public class GroupList implements java.io.Serializable {

    // Increment UID version id when changing this file
    private static final long serialVersionUID = 0L;
    private Hashtable<String, Group> list = new Hashtable<String, Group>(); //<groupName, Group>

    public synchronized void addGroup(String username, String groupName) {
        Group newGroup = new Group(username);
        list.put(groupName, newGroup);
    }
    public synchronized void deleteGroup(String groupName) {
        list.remove(groupName);
    }
    // Given the group name returns whether the group exists or not
    public synchronized boolean checkGroup(String groupName) {
        if(list.containsKey(groupName)) {
            return true;
        } else {
            return false;
        }
    }

    public synchronized ArrayList<String> getGroupMembers(String groupName) {
        return list.get(groupName).getMembers();
    }

    public synchronized String getGroupOwner(String groupName) {
        return list.get(groupName).getOwner();
    }

    public synchronized void addMember(String username, String groupName) {
        list.get(groupName).addMember(username);
    }

    // If the user to be removed is the owner, the group is deleted and all members removed
    // ASSUMPTION RIGHT NOW that each user's list of groups (user.groups in UserList) is updated
    // (i.e. this group is removed from their list of groups) elsewhere to reflect the group deletion!!!!
    public void removeMember(String username, String groupName) {
        if (list.get(groupName).owner.equals(username)) { // if member to be removed is the owner
            list.remove(groupName); 
        } else {
            list.get(groupName).removeMember(username);
        }
    }

     

    class Group implements java.io.Serializable {

        /**
         *
         */
        // Copied serialVersionUID for now, maybe change it later
        private static final long serialVersionUID = -6699986336399821598L;
        private ArrayList<String> members;
        private String owner; // Each group has an owner who is the user who created it
        
        // boolean createGroup(String groupname, UserToken token)
        Group(String username) {
            members = new ArrayList<String>();
            owner = username;
        }

        public ArrayList<String> getMembers() {
            return members;
        }

        public String getOwner() {
            return owner;
        }

        public void addMember(String username) {
            members.add(username);
        }

        public void removeMember(String username) {
            if(!members.isEmpty()) {
                if(members.contains(username)){
                    members.remove(members.indexOf(username));
                }
            }
        }

        // Taha: As far as I can tell there is no way to transfer or remove ownership
        // short of removing the owner thereby deleting the group

    }

    
}
