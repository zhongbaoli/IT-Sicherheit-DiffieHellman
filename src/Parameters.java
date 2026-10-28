import java.math.BigInteger;

public class Parameters {
    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger order;

    public Parameters(BigInteger modulus, BigInteger generator, BigInteger order) {
        this.modulus = modulus;
        this.generator = generator;
        this.order = order;
    }

    public Parameters(int modulus, int generator, int order) {
        //TODO Auto-generated constructor stub
        this.modulus = BigInteger.valueOf(modulus);
        this.generator = BigInteger.valueOf(generator);
        this.order = BigInteger.valueOf(order);
    }

    public BigInteger getModulus(){
        return modulus;
    }
    public BigInteger getGenerator(){
        return generator;
    }
    public BigInteger getOrder(){
        return order;
    }
}
