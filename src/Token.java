import java.util.List;

public class Token implements java.io.Serializable, UserToken{

    // Copy of another version id for now, maybe change later?
    private static final long serialVersionUID = -6699986336399821598L;

    private String issuer;
    private String subject;
    private List<String> groups;

    Token(String issuer, String subject, List<String> groups) {
        this.issuer = issuer;
        this.subject = subject;
        this.groups = groups;

    }
    
    // The name of the server that issued the token
    public String getIssuer() {
        return issuer;
    }

    // Returns the username of the user who the token is issued to
    public String getSubject() {
        return subject;
    }

    // Returns the list of groups the user is a part of (and therefore has access to)
    public List<String> getGroups() {
        return groups;
    }


}
