package dh;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class KeyExchange {

    // =========================================================================
    // ENUMS
    // =========================================================================
    public enum AttackType {
        NONE,
        ATTACK_1, // geändertes g, um eine kleine Untergruppe zu erzwingen
        ATTACK_2, // ungeeignetes p
        ATTACK_3, // statischer privateKey über mehrere Sitzungen
    } 

    public enum ValidationMode {
        NONE,
        VALIDATE
    }

    // =========================================================================
    // FELDER DER KEYEXCHANGE-KLASSE
    // =========================================================================
    private Parameters parameters;
    private AttackType attackType;
    private ValidationMode validationMode;

    private static final BigInteger STATIC_ALICE_PRIVATE_KEY = new BigInteger("1234567890ABCDEF1234567890ABCDEF", 16);
    private static final BigInteger STATIC_BOB_PRIVATE_KEY = new BigInteger("FEDCBA0987654321FEDCBA0987654321", 16);


    // =========================================================================
    // KONSTRUKTOREN & KONFIGURATION
    // =========================================================================
    public KeyExchange() {
        this.parameters = Parameters.createStandard512Bit();
        this.attackType = AttackType.NONE;
        this.validationMode = ValidationMode.NONE;
    }

    public KeyExchange setParameters(Parameters parameters) {
        this.parameters = parameters;
        return this;
    }

    public KeyExchange setAttackType(AttackType attackType) {
        this.attackType = attackType;
        return this;
    }

    public KeyExchange setValidationMode(ValidationMode validationMode) {
        this.validationMode = validationMode;
        return this;
    }

    private BigInteger injectedAttackerValue = null; // Neuer Wert für gezielte Angriffe

    public KeyExchange setInjectedAttackerValue(BigInteger value) {
        this.injectedAttackerValue = value;
        return this;
    }

    private BigInteger customBobPrivateKey = null;
    private byte[] lastBobSessionKey = null;

    public KeyExchange setCustomBobPrivateKey(BigInteger key) {
        this.customBobPrivateKey = key;
        return this;
    }

    public KeyExchange setBobPrivateKey(BigInteger key) {
        return setCustomBobPrivateKey(key);
    }

    public byte[] getLastBobSessionKey() {
        return this.lastBobSessionKey;
    }

    /**
     * Ermittelt den Rest (Bob's Private Key % SubgroupOrder) direkt aus dieser Sitzung.
     * Berechnet die Untergruppenordnung automatisch.
     */
    public int deduceRemainder() {
        if (injectedAttackerValue == null || lastBobSessionKey == null || parameters == null) {
            throw new IllegalStateException("Sitzung wurde noch nicht ausgeführt oder erforderliche Werte fehlen.");
        }
        return deduceRemainder(injectedAttackerValue, parameters.modulus, lastBobSessionKey);
    }

    /**
     * Ermittelt den Rest (Bob's Private Key % SubgroupOrder) direkt aus dieser Sitzung
     * mit einer vorgegebenen Untergruppenordnung.
     */
    public int deduceRemainder(int subgroupOrder) {
        if (injectedAttackerValue == null || lastBobSessionKey == null || parameters == null) {
            throw new IllegalStateException("Sitzung wurde noch nicht ausgeführt oder erforderliche Werte fehlen.");

        }
        return deduceRemainder(injectedAttackerValue, subgroupOrder, parameters.modulus, lastBobSessionKey);
    }

    

    // =========================================================================
    // Schlüsselaustausch (Run)
    // =========================================================================
    public void run() {
        System.out.println("Starte Diffie-Hellman-Schlüsselaustausch...");
        System.out.println("Angriffstyp: " + attackType);
        System.out.println("Validierungsmodus: " + validationMode);
        System.out.println("Verwendete Parameter: g = " + parameters.generator + ", p = " + parameters.modulus);

        try {
            // 1. SETUP DER PARAMETER
            Parameters activeParameters = this.parameters;

            // 1.1 ANGRIFF 2: p ist nicht prim
            if (attackType == AttackType.ATTACK_2) {
                activeParameters = Parameters.createNonPrimeModulus();
            }

            // 1.2 VALIDIERUNG DER PARAMETER
            if (validationMode == ValidationMode.VALIDATE) {
                Validator.validateParameters(activeParameters.modulus, activeParameters.generator);
            } else {
                System.out.println("\n-> Keine Validierung der Gruppenparameter durchgeführt.");
            }

            // 2. SCHLÜSSELGENERIERUNG
            BigInteger alicePrivateKey, bobPrivateKey;

            // 2.1 ANGRIFF 3: Statische Schlüssel über mehrere Sitzungen
            if (attackType == AttackType.ATTACK_3) {
                // Beispiel für einen Angriff: Verwende statische Schlüssel
                alicePrivateKey = STATIC_ALICE_PRIVATE_KEY;
                bobPrivateKey = (customBobPrivateKey != null) ? customBobPrivateKey : STATIC_BOB_PRIVATE_KEY;
            } else {
                SecureRandom random = new SecureRandom();
                alicePrivateKey = new BigInteger(activeParameters.modulus.bitLength() - 1, random);
                bobPrivateKey = new BigInteger(activeParameters.modulus.bitLength() - 1, random);
            }

            // 2.2 VALIDIERUNG DER PRIVATEN SCHLÜSSEL
            if (validationMode == ValidationMode.VALIDATE) {
                Validator.validatePrivateKey(alicePrivateKey, activeParameters.modulus, "Alice");
                Validator.validatePrivateKey(bobPrivateKey, activeParameters.modulus, "Bob");
            } else {
                System.out.println("\n-> Keine Validierung der privaten Schlüssel durchgeführt.");
            }
            
            // 3. BERECHNUNG DER ÖFFENTLICHEN WERTE
            BigInteger alicePublicKey = activeParameters.generator.modPow(alicePrivateKey, activeParameters.modulus);
            BigInteger bobPublicKey = activeParameters.generator.modPow(bobPrivateKey, activeParameters.modulus);

            System.out.println("\n[Schlüsselerzeugung]");
            System.out.println("  • Alices öffentlicher Wert A: " + truncateHex(alicePublicKey));
            System.out.println("  • Bobs öffentlicher Wert B:   " + truncateHex(bobPublicKey));

            BigInteger aliceReceivedPublicKey = bobPublicKey;
            BigInteger bobReceivedPublicKey = alicePublicKey;

            // 3.1 ANGRIFF: MANIPULATION DER ÖFFENTLICHEN WERTE
            if (attackType == AttackType.ATTACK_1 || attackType == AttackType.ATTACK_3) {
                
                // Wenn ein spezieller Wert gesetzt wurde, nimm diesen. Sonst standardmäßig p-1.
                BigInteger maliciousValue = (injectedAttackerValue != null) 
                                            ? injectedAttackerValue 
                                            : activeParameters.modulus.subtract(BigInteger.ONE);
                
                // Angreifer fängt Werte ab und sendet seinen manipulierten Wert an Bob & Alice
                bobReceivedPublicKey = maliciousValue;
                aliceReceivedPublicKey = maliciousValue;
                
                System.out.println("\n[ANGRIFF] Angreifer fängt den Schlüsselaustausch ab!");
                System.out.println(" [ANGRIFF] Er sendet stattdessen " + maliciousValue + " an die Parteien.");
            }

            // 3.2 WERTEVALIDIERUNG VOR BERECHNUNG
            if (validationMode == ValidationMode.VALIDATE) {
                Validator.validatePublicValue(aliceReceivedPublicKey, activeParameters.modulus, "Alice");
                Validator.validatePublicValue(bobReceivedPublicKey, activeParameters.modulus, "Bob");
            } else {
                System.out.println("\n-> Keine Validierung der öffentlichen Werte durchgeführt.");
            }

            // 4. GEHEIMNISBERECHNUNG
            BigInteger aliceRawSecret = aliceReceivedPublicKey.modPow(alicePrivateKey, activeParameters.modulus);
            BigInteger bobRawSecret = bobReceivedPublicKey.modPow(bobPrivateKey, activeParameters.modulus);

            byte[] aliceKey = deriveSHA256Key(aliceRawSecret);
            byte[] bobKey   = deriveSHA256Key(bobRawSecret);

            this.lastBobSessionKey = bobKey; // Speichere Bobs Sitzungsschlüssel für mögliche spätere Angriffe

            System.out.println("\n[Ergebnisse]");
            System.out.println("  • Alices rohes K: " + truncateHex(aliceRawSecret));
            System.out.println("  • Bobs rohes K:   " + truncateHex(bobRawSecret));
            System.out.println("  • Alices Sitzungsschlüssel: " + HexFormat.of().formatHex(aliceKey));
            System.out.println("  • Bobs Sitzungsschlüssel:   " + HexFormat.of().formatHex(bobKey));

            boolean keysMatch = MessageDigest.isEqual(aliceKey, bobKey);
            System.out.println("\n==> Ergebnis: Sitzungsschlüssel stimmen überein? " + keysMatch);

            if (attackType == AttackType.ATTACK_1 && validationMode == ValidationMode.NONE) {
                System.out.println("[ANGRIFF] Angriff 2 war erfolgreich! Das Geheimnis K wurde auf den festen Wert " + aliceRawSecret + " gezwungen!");
            }
            
        } catch (SecurityException e) {
            System.out.println("\n SCHUTZMECHANISMUS GREIFT:");
            System.out.println("   " + e.getMessage());
            System.out.println("==> Der Schlüsselaustausch wurde sicher abgebrochen.");
        }
        System.out.println("========================================================================\n");
    }

    public static byte[] deriveSHA256Key(BigInteger secret) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(secret.toByteArray());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String truncateHex(BigInteger value) {
        if (value == null) return "null";
        String hex = value.toString(16);
        if (hex.length() > 24) {
            return hex.substring(0, 24) + "...";
        }
        return hex;
    }

    // =========================================================================
    // ANGRIFF 3: UNTERGRUPPEN-REKONSTRUKTION & CRT
    // =========================================================================

    public static void simulateAttack3CRT(BigInteger secretBobKey, ValidationMode validationMode) {
        // Setup für die Demo: p = 31 (damit p - 1 = 30 = 2 * 3 * 5), g = 3
        Parameters demoParams = new Parameters(3, 31);
        int[] injectedValues = {30, 25, 16};
        int[] subgroupOrders = {2, 3, 5};
        int[] remainders = new int[3];

        for (int i = 0; i < injectedValues.length; i++) {
            System.out.printf("\n--- SITZUNG %d (Angreifer sendet %d, erzeugt %der Gruppe) ---\n",
                    i + 1, injectedValues[i], subgroupOrders[i]);

            KeyExchange session = new KeyExchange()
                .setParameters(demoParams)
                .setBobPrivateKey(secretBobKey)
                .setAttackType(AttackType.ATTACK_3)
                .setValidationMode(validationMode)
                .setInjectedAttackerValue(BigInteger.valueOf(injectedValues[i]));
            session.run();

            remainders[i] = session.deduceRemainder(subgroupOrders[i]);
        }

        System.out.println("\n [ANGRIFF 3 - FINALE] Chinesischer Restsatz wird angewendet...");
        System.out.println("Angreifer weiß nun:");
        for (int i = 0; i < remainders.length; i++) {
            System.out.println("Bob's Private Key % " + subgroupOrders[i] + " = " + remainders[i]);
        }

        BigInteger recovered = solveCRT(remainders, subgroupOrders);
        System.out.println("==> BINGO! Der Angreifer hat Bobs statischen privaten Schlüssel berechnet: " + recovered);
    }

    public static int calculateSubgroupOrder(BigInteger injectedValue, BigInteger p) {
        BigInteger current = injectedValue.mod(p);
        if (current.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Wert darf nicht durch p teilbar sein.");
        }

        int order = 1;
        while (!current.equals(BigInteger.ONE)) {
            current = current.multiply(injectedValue).mod(p);
            order++;
        }
        return order;
    }

    public static int deduceRemainder(BigInteger injectedValue, BigInteger p, byte[] bobSessionKey) {
        int subgroupOrder = calculateSubgroupOrder(injectedValue, p);
        return deduceRemainder(injectedValue, subgroupOrder, p, bobSessionKey);
    }

    public static int deduceRemainder(BigInteger injectedValue, int subgroupOrder, BigInteger p, byte[] bobSessionKey) {
        for (int r = 0; r < subgroupOrder; r++) {
            BigInteger candidateSecret = injectedValue.modPow(BigInteger.valueOf(r), p);
            byte[] candidateKey = deriveSHA256Key(candidateSecret);

            if (MessageDigest.isEqual(candidateKey, bobSessionKey)) {
                return r;
            }
        }
        throw new IllegalStateException("Kein passender Rest in der Untergruppe gefunden.");
    }

    /**
     * Kompatibilitätsmethode für bestehende Aufrufe (z.B. aus dem Notebook).
     */
    public static int determineRemainderFromSession(KeyExchange session, BigInteger injectedValue, int subgroupOrder, BigInteger p) {
        return deduceRemainder(injectedValue, subgroupOrder, p, session.getLastBobSessionKey());
    }

    /**
     * Kompatibilitätsmethode für bestehende Aufrufe (z.B. aus dem Notebook).
     */
    public static int determineRemainderFromSession(KeyExchange session, BigInteger injectedValue, BigInteger p) {
        return deduceRemainder(injectedValue, p, session.getLastBobSessionKey());
    }

    public static BigInteger solveCRT(int[] remainders, int[] moduli) {
        int product = 1;
        for (int m : moduli) {
            product *= m;
        }
        for (int candidate = 1; candidate < product; candidate++) {
            boolean match = true;
            for (int i = 0; i < remainders.length; i++) {
                if (candidate % moduli[i] != remainders[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return BigInteger.valueOf(candidate);
            }
        }
        return BigInteger.valueOf(-1);
    }
}
