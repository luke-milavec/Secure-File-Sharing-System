import java.io.Serializable;

public class SignedToken implements Serializable {
    private final byte[] tokenBytes;
    private final byte[] tokenSignature;

    public SignedToken(byte[] tokenBytes, byte[] tokenSignature) {
        this.tokenBytes = tokenBytes;
        this.tokenSignature = tokenSignature;
    }

    public byte[] getTokenBytes() {
        return tokenBytes;
    }

    public byte[] getTokenSignature() {
        return tokenSignature;
    }
}
