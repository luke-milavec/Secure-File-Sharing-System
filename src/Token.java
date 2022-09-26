import java.util.List;

public class Token implements UserToken{
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
