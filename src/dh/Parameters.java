package dh;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Parameters {

    public final BigInteger generator;
    public final BigInteger modulus;
    

    public Parameters(BigInteger generator, BigInteger modulus) {
        this.generator = generator;
        this.modulus = modulus;
    }

    // Konvertiert eigegebene Int Werte in BigInteger
    public Parameters(int generator, int modulus) {
        this.generator = BigInteger.valueOf(generator);
        this.modulus = BigInteger.valueOf(modulus);
    }

    public static Parameters createStandard512Bit() {
        BigInteger p = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16
        );
        BigInteger g = BigInteger.valueOf(2);
        return new Parameters(g, p);
    }

    public static Parameters createNonPrimeModulus(){
        BigInteger compositeP = BigInteger.valueOf(1000000007L).multiply(BigInteger.valueOf(1000000009L)); // Zusammengesetzte Zahl
        BigInteger g = BigInteger.valueOf(2);
        return new Parameters(g, compositeP);
    }

    public static Parameters createSmall31Bit() {
        return new Parameters(3, 31);
    }

    public void printGroupAndSubgroup(BigInteger p, BigInteger g) {
        System.out.println("==================================================");
        System.out.println("GRUPPEN- UND UNTERGRUPPEN-ANALYSE");
        System.out.println("==================================================");
        System.out.println("Parameter: \n- Modulus p = " + p);
        System.out.println("Parameter: \n- Generator g = " + g);

        // 1. HAUPTGRUPPE ℤₚ*
        BigInteger mainGroupOrder = p.subtract(BigInteger.ONE); // Ordnung der Hauptgruppe: p - 1
        System.out.println("\n--- HAUPTGRUPPE ---");
        System.out.println("  - Ordnung (Anzahl Elemente): " + mainGroupOrder);

        // 2. UNTERGRUPPE <g>
        System.out.println("\n--- UNTERGRUPPE <g> (erzeugt durch g = " + g + ") ---");
        List<BigInteger> subgroupElements = new ArrayList<>();
        BigInteger current = g.mod(p);
        
        // Iterativ g^k mod p berechnen, bis sich das Element wiederholt
        if (p.compareTo(BigInteger.valueOf(1000)) < 0) {
            while (!subgroupElements.contains(current)) {
                subgroupElements.add(current);
                current = current.multiply(g).mod(p);
            }
            
            int subgroupOrder = subgroupElements.size();
            System.out.println("  - Ordnung der Untergruppe: " + subgroupOrder);
            System.out.println("  - Erzeugte Elemente <g>:    " + subgroupElements);
            
            // Prüfung, ob g ein primitiver Erzeuger der gesamten Hauptgruppe ist
            if (BigInteger.valueOf(subgroupOrder).equals(mainGroupOrder)) {
                System.out.println("  ==> STATUS: g = " + g + " ist ein VOLLSTÄNDIGER Generator der Hauptgruppe!");
            } else {
                System.out.println("  ==> WARNUNG: g = " + g + " erzeugt nur eine KLEINE Untergruppe der Ordnung " + subgroupOrder + "!");
            }
        } else {
            System.out.println("- Hinweis: Für große Parameter wird die Ordnung der Untergruppe über die mathematischen Faktoren von (p-1) bestimmt.");
        }
        System.out.println("==================================================\n");
    }
}
