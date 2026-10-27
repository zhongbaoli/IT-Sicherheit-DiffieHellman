import java.math.BigInteger;

public class Parameters {
    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger gruppenordnung;

    public Parameters(BigInteger modulus, BigInteger generator, BigInteger gruppenordnung) {
        this.modulus = modulus;
        this.generator = generator;
        this.gruppenordnung = gruppenordnung;
    }
}
