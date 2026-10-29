import java.math.BigInteger;

public class Participant {

    private final Parameters parameters;
    private final BigInteger privateKey;

    public Participant(Parameters parameters,BigInteger privateKey) {
        this.parameters = parameters;
        this.privateKey = privateKey;
    }

    public BigInteger getPublicKey() {
        // generator^privateKey mod modulus
        return parameters.generator.modPow(
            privateKey, parameters.modulus
        );
    }

    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        // generator^otherPublicKey mod modulus
        return otherPublicKey.modPow(
            privateKey, parameters.modulus
        );
    }
}