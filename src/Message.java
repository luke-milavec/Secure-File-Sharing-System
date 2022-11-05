import java.io.Serializable;

public class Message implements Serializable {

    // Taken from envelope, does it matter?
    private static final long serialVersionUID = -7726335089122193104L;
    public String hmac;
    public String enc;
    
    public Message(String h, String e){
        hmac = h;
        enc = e;
    }
}
