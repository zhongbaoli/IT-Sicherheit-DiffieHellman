import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Parameters {
    private BigInteger generator; // Base
    private BigInteger modulus;
    
    public Parameters(BigInteger generator, BigInteger modulus) {
        this.generator = generator;
        this.modulus = modulus;
    }

    public Parameters(int generator, int modulus) {
        //TODO Auto-generated constructor stub
        this.generator = BigInteger.valueOf(generator);
        this.modulus = BigInteger.valueOf(modulus);
    }

    public BigInteger getGenerator(){
        return generator;
    }

    public BigInteger getModulus(){
        return modulus;
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
