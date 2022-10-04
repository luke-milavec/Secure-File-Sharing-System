/* This list represents the users on the server */
import java.util.ArrayList;
import java.util.Hashtable;

public class UserList implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 7600343803563417992L;
    private Hashtable<String, User> list = new Hashtable<String, User>();

    public synchronized void addUser(String username) {
        User newUser = new User();
        list.put(username, newUser);
        System.err.println("in list addUser(): " + list.toString());
    }

    public synchronized void deleteUser(String username) {
        list.remove(username);
        System.err.println("in list deleteUser(): " + list.toString());
    }

    public synchronized boolean checkUser(String username) {
        System.err.println(" debug in userlist checkUser(): " + list.toString());
        if(list.containsKey(username)) {
            return true;
        } else {
            System.err.println("User " + username +  " does not exist");
            return false;
        }
    }

    public synchronized ArrayList<String> getUserGroups(String username) {
        System.err.println(" Debug in list getUsergroups(): " + list.get(username).getGroups().toString());
        return list.get(username).getGroups();
        
    }

    public synchronized ArrayList<String> getUserOwnership(String username) {
        return list.get(username).getOwnership();
    }

    public synchronized void addGroup(String user, String groupname) {
        list.get(user).addGroup(groupname);
    }

    public synchronized void removeGroup(String user, String groupname) {
        list.get(user).removeGroup(groupname);
    }

    public synchronized void addOwnership(String user, String groupname) {
        list.get(user).addOwnership(groupname);
    }

    public synchronized void removeOwnership(String user, String groupname) {
        list.get(user).removeOwnership(groupname);
    }


    class User implements java.io.Serializable {

        /**
         *
         */
        private static final long serialVersionUID = -6699986336399821598L;
        private ArrayList<String> groups;
        private ArrayList<String> ownership;

        public User() {
            groups = new ArrayList<String>();
            ownership = new ArrayList<String>();
        }

        public ArrayList<String> getGroups() {
            return groups;
        }

        public ArrayList<String> getOwnership() {
            return ownership;
        }

        public void addGroup(String group) {
            groups.add(group);
        }

        public void removeGroup(String group) {
            if(!groups.isEmpty()) {
                if(groups.contains(group)) {
                    groups.remove(groups.indexOf(group));
                }
            }
        }

        public void addOwnership(String group) {
            ownership.add(group);
        }

        public void removeOwnership(String group) {
            if(!ownership.isEmpty()) {
                if(ownership.contains(group)) {
                    ownership.remove(ownership.indexOf(group));
                }
            }
        }

    }

}
