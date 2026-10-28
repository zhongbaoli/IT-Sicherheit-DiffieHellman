import java.math.BigInteger;

public class Participant {

    private final Parameters parameters;
    private final BigInteger privateKey;

    public Participant(Parameters parameters,BigInteger privateKey) {
        this.parameters = parameters;
        this.privateKey = privateKey;
    }

    public BigInteger getPublicKey() {
        return parameters.getOrder().modPow(
            privateKey, parameters.getModulus()
        );
    }

    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        return otherPublicKey.modPow(
            privateKey, parameters.getModulus()
        );
    }
}