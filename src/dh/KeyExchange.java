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

    // =========================================================================
    // FELDER DER KEYEXCHANGE-KLASSE
    // =========================================================================
    private Parameters parameters;
    private AttackType attackType;
    private boolean validate;

    private static final BigInteger STATIC_ALICE_PRIVATE_KEY = new BigInteger("1234567890ABCDEF1234567890ABCDEF", 16);
    private static final BigInteger STATIC_BOB_PRIVATE_KEY = new BigInteger("FEDCBA0987654321FEDCBA0987654321", 16);


    // =========================================================================
    // KONSTRUKTOREN & KONFIGURATION
    // =========================================================================

    private record PrivateKeys(
        BigInteger alice,
        BigInteger bob
    ) {}

    private record PublicKeys(
        BigInteger alice,
        BigInteger bob
    ) {}

    private record ReceivedKeys(
        BigInteger receivedByAlice,
        BigInteger receivedByBob
    ) {}

    private record SessionResult(
        BigInteger aliceRawSecret,
        BigInteger bobRawSecret,
        byte[] aliceKey,
        byte[] bobKey
    ) {}


    public KeyExchange() {
        this.parameters = Parameters.createStandard512Bit();
        this.attackType = AttackType.NONE;
        this.validate = false;
    }

    public KeyExchange setParameters(Parameters parameters) {
        this.parameters = parameters;
        return this;
    }

    public KeyExchange setAttackType(AttackType attackType) {
        this.attackType = attackType;
        return this;
    }

    public KeyExchange setValidate(boolean wantValidation) {
        this.validate = wantValidation;
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
        System.out.println("Validierung aktiviert: " + validate);

        try {
            // 1. Parameter auswählen und prüfen
            Parameters activeParameters = setupParameters();
            validateParameters(activeParameters);

            // 2. Private Schlüssel erzeugen und prüfen
            PrivateKeys privateKeys = generatePrivateKeys(activeParameters);
            validatePrivateKeys(privateKeys, activeParameters);

            // 3. Öffentliche Schlüssel berechnen
            PublicKeys publicKeys = generatePublicKeys(privateKeys, activeParameters);

            // 4. Möglichen Angriff simulieren
            ReceivedKeys receivedKeys = simulateAttacker(publicKeys, activeParameters);

            // 5. Empfangene Werte prüfen
            validateReceivedKeys(receivedKeys, activeParameters);

            // 6. Sitzungsschlüssel berechnen
            SessionResult result = calculateSessionKeys(privateKeys, receivedKeys, activeParameters);

            // 7. Ergebnisse ausgeben
            printResults(result);

        } catch (SecurityException e) {
            System.out.println("\nSCHUTZMECHANISMUS GREIFT:");
            System.out.println("   " + e.getMessage());
            System.out.println("==> Der Schlüsselaustausch wurde abgebrochen.");
        }

        System.out.println("========================================================================\n");
    }

    private Parameters setupParameters() {
        Parameters result;
        if (attackType == AttackType.ATTACK_2) {
            result = Parameters.createNonPrimeModulus();
        } else { 
            result = this.parameters;
        }
        System.out.println("Verwendete Parameter: g = " + result.generator
        + ", p = " + result.modulus);

        return result;
    }

    private void validateParameters(Parameters params) {
        if (validate) {
            Validator.validateParameters(
                params.modulus,
                params.generator
            );
        } else {
            System.out.println("\n-> Keine Validierung der Gruppenparameter durchgeführt.");
        }

    }

    private PrivateKeys generatePrivateKeys(Parameters params) {
        BigInteger alicePrivateKey;
        BigInteger bobPrivateKey;

        if (attackType == AttackType.ATTACK_3) {

            alicePrivateKey = STATIC_ALICE_PRIVATE_KEY;
            bobPrivateKey = (customBobPrivateKey != null)
                ? customBobPrivateKey
                : STATIC_BOB_PRIVATE_KEY;

        } else {
            SecureRandom random = new SecureRandom();

            alicePrivateKey = new BigInteger(
                params.modulus.bitLength() - 1, random
            );

            bobPrivateKey = new BigInteger(
                params.modulus.bitLength() - 1, random
            );
        }

        return new PrivateKeys(alicePrivateKey, bobPrivateKey);
    }

    private void validatePrivateKeys(PrivateKeys privateKeys, Parameters params) {

        if (validate) {
            Validator.validatePrivateKey(
                privateKeys.alice(), params.modulus, "Alice"
            );

            Validator.validatePrivateKey(
                privateKeys.bob(), params.modulus, "Bob"
            );
        } else {
            System.out.println("\n-> Keine Validierung der privaten Schlüssel durchgeführt.");
        }
    }

    private PublicKeys generatePublicKeys(PrivateKeys privateKeys, Parameters params) {

        BigInteger alicePublicKey = params.generator.modPow(privateKeys.alice(), params.modulus);
        BigInteger bobPublicKey = params.generator.modPow(privateKeys.bob(), params.modulus);

        System.out.println("\n[Schlüsselerzeugung]");
        System.out.println(" Alices öffentlicher Wert A: "
            + truncateHex(alicePublicKey));
        System.out.println(" Bobs öffentlicher Wert B: "
            + truncateHex(bobPublicKey));

        return new PublicKeys(alicePublicKey, bobPublicKey);
    }

    private ReceivedKeys simulateAttacker(
            PublicKeys publicKeys,
            Parameters params) {

        BigInteger aliceReceived = publicKeys.bob();
        BigInteger bobReceived = publicKeys.alice();

        if (attackType == AttackType.ATTACK_1 || attackType == AttackType.ATTACK_3) {
            BigInteger maliciousValue = (injectedAttackerValue != null)
                    ? injectedAttackerValue
                    : params.modulus.subtract(BigInteger.ONE);

                aliceReceived = maliciousValue;
                bobReceived = maliciousValue;

                System.out.println();
                System.out.println("[ANGRIFF] Öffentliche Werte manipuliert!");
                System.out.println("[ANGRIFF] Eingeschleuster Wert: "
                    + maliciousValue);
        }
        return new ReceivedKeys(aliceReceived, bobReceived);
    }

    private void validateReceivedKeys(
            ReceivedKeys receivedKeys,
            Parameters params) {

        if (validate) {
            Validator.validatePublicValue(receivedKeys.receivedByAlice(),params.modulus,"Alice");
            Validator.validatePublicValue(receivedKeys.receivedByBob(), params.modulus, "Bob");
        } else {
            System.out.println();
            System.out.println("-> Keine Validierung der öffentlichen Werte durchgeführt.");
        }
    }

    private SessionResult calculateSessionKeys(PrivateKeys privateKeys, ReceivedKeys receivedKeys, Parameters params) {

        BigInteger aliceRawSecret =
            receivedKeys.receivedByAlice().modPow(
                privateKeys.alice(), params.modulus
            );

        BigInteger bobRawSecret = 
            receivedKeys.receivedByBob().modPow(privateKeys.bob(), params.modulus);

        byte[] aliceKey = deriveSHA256Key(aliceRawSecret);
        byte[] bobKey = deriveSHA256Key(bobRawSecret);

        this.lastBobSessionKey = bobKey;

        return new SessionResult(
            aliceRawSecret,
            bobRawSecret,
            aliceKey,
            bobKey
        );
    }

    private void printResults(SessionResult result) {
        System.out.println("");
        System.out.println("");
        System.out.println("Ergebnisse");

        System.out.println("Alices rohes K: "
            + truncateHex(result.aliceRawSecret()));

        System.out.println("Bobs rohes K:   "
            + truncateHex(result.bobRawSecret()));

        System.out.println("Alices Sitzungsschlüssel: "
            + HexFormat.of().formatHex(result.aliceKey()));

        System.out.println("Bobs Sitzungsschlüssel:   "
            + HexFormat.of().formatHex(result.bobKey()));

        boolean keysMatch = MessageDigest.isEqual(
            result.aliceKey(),
            result.bobKey()
        );

        System.out.println("");
        System.out.println("==> Ergebnis: Sitzungsschlüssel stimmen überein? " + keysMatch);

        if (attackType == AttackType.ATTACK_1 && !validate) {
            System.out.println("ANGRIFF Die empfangenen öffentlichen Werte wurden manipuliert.");
        }
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

    public static void simulateAttack3CRT(BigInteger secretBobKey, boolean validate) {
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
                .setValidate(validate)
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
