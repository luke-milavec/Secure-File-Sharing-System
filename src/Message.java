public class Message{
    public String hmac;
    public String enc;
    
    public Message(String h, String e){
        hmac = h;
        enc = e;
    }
}
