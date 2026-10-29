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
        ALL
    } 

    public enum ValidationMode {
        NONE,
        VALIDATE_PARAMETERS,
        VALIDATE_PUBLIC_VALUES,
        BOTH
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

    // =========================================================================
    // Schlüsselaustausch (Run)
    // =========================================================================
    public void run() {
        System.out.println("Starte Diffie-Hellman-Schlüsselaustausch...");
        System.out.println("Verwendete Parameter: p = " + parameters.modulus + ", g = " + parameters.generator);
        System.out.println("Angriffstyp: " + attackType);
        System.out.println("Validierungsmodus: " + validationMode);

        try {
            // 1. SETUP DER PARAMETER (Angriff 2 verändert die Parameter)
            Parameters activeParameters = this.parameters;
            //@Krushali
            if (attackType == AttackType.ATTACK_2 || attackType == AttackType.ALL) {
                // Beispiel für einen Angriff: Verwende ein unsicheres p
                activeParameters = Parameters.createNonPrimeModulus();
            }

            // 2. VALIDIERUNG DER PARAMETER (falls Validierungsmodus == VALIDATE_PARAMETERS)
            if (validationMode == ValidationMode.VALIDATE_PARAMETERS || validationMode == ValidationMode.BOTH) {
                Validator.validateParameters(activeParameters.modulus, activeParameters.generator);
            } else {
                System.out.println("-> Keine Validierung der Gruppenparameter durchgeführt.");
            }

            // 3. SCHLÜSSELGENERIERUNG (Angriff 3 nutzt erzwungene statische Schlüssel)
            BigInteger alicePrivateKey, bobPrivateKey;
            //@Krushali
            if (attackType == AttackType.ATTACK_3 || attackType == AttackType.ALL) {
                // Beispiel für einen Angriff: Verwende statische Schlüssel
                alicePrivateKey = STATIC_ALICE_PRIVATE_KEY;
                bobPrivateKey = STATIC_BOB_PRIVATE_KEY;
            } else {
                SecureRandom random = new SecureRandom();
                alicePrivateKey = new BigInteger(activeParameters.modulus.bitLength() - 1, random);
                bobPrivateKey = new BigInteger(activeParameters.modulus.bitLength() - 1, random);
            }

            BigInteger alicePublicKey = activeParameters.generator.modPow(alicePrivateKey, activeParameters.modulus);
            BigInteger bobPublicKey = activeParameters.generator.modPow(bobPrivateKey, activeParameters.modulus);

            System.out.println("\n[Schlüsselerzeugung]");
            System.out.println("  • Alices öffentlicher Wert A: " + truncateHex(alicePublicKey));
            System.out.println("  • Bobs öffentlicher Wert B:   " + truncateHex(bobPublicKey));

            // 4. ANGRIFF 1: MANIPULATION DER ÖFFENTLICHEN WERTE (Erzeugen einer kleinen Untergruppe)
            BigInteger aliceReceivedPublicKey = bobPublicKey;
            BigInteger bobReceivedPublicKey = alicePublicKey;

            //@Krushali
            if (attackType == AttackType.ATTACK_1 || attackType == AttackType.ALL) {
                aliceReceivedPublicKey = BigInteger.ONE; // Injizierter Wert durch Angreifer 
            }

            // 5. WERTEVALIDIERUNG VOR BERECHNUNG (falls Validierungsmodus == VALIDATE_PUBLIC_VALUES)
            if (validationMode == ValidationMode.VALIDATE_PUBLIC_VALUES  || validationMode == ValidationMode.BOTH) {
                Validator.validatePublicValue(aliceReceivedPublicKey, activeParameters.modulus);
                Validator.validatePublicValue(bobReceivedPublicKey, activeParameters.modulus);
            }

            // 6. GEHEIMNISBERECHNUNG
            BigInteger aliceRawSecret = aliceReceivedPublicKey.modPow(alicePrivateKey, activeParameters.modulus);
            BigInteger bobRawSecret = bobReceivedPublicKey.modPow(bobPrivateKey, activeParameters.modulus);

            byte[] aliceKey = deriveSHA256Key(aliceRawSecret);
            byte[] bobKey   = deriveSHA256Key(bobRawSecret);

            System.out.println("\n[Ergebnisse]");
            System.out.println("  • Alices rohes K: " + truncateHex(aliceRawSecret));
            System.out.println("  • Bobs rohes K:   " + truncateHex(bobRawSecret));
            System.out.println("  • Alices Sitzungsschlüssel: " + HexFormat.of().formatHex(aliceKey));
            System.out.println("  • Bobs Sitzungsschlüssel:   " + HexFormat.of().formatHex(bobKey));

            boolean keysMatch = MessageDigest.isEqual(aliceKey, bobKey);
            System.out.println("\n==> Ergebnis: Sitzungsschlüssel stimmen überein? " + keysMatch);

            if (attackType == AttackType.ATTACK_1 && validationMode == ValidationMode.NONE || validationMode == ValidationMode.VALIDATE_PARAMETERS) {
                System.out.println("⚠️ WARNUNG: Angriff 2 war erfolgreich! Das Geheimnis K wurde auf den festen Wert " + aliceRawSecret + " gezwungen!");
            }
            
        } catch (SecurityException e) {
            System.out.println("\n🛑 SCHUTZMECHANISMUS GREIFT:");
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

    public static void main(String[] args) {
        // Beispiel 1: Normaler Ablauf ohne Fehler
        new KeyExchange()
            .setAttackType(AttackType.NONE)
            .setValidationMode(ValidationMode.NONE)
            .run();

        // Beispiel 2: Angriff 2 OHNE Prüfung (K wird auf 1 erzwungen)
        new KeyExchange()
            .setAttackType(AttackType.ATTACK_2)
            .setValidationMode(ValidationMode.NONE)
            .run();

        // Beispiel 3: Angriff 2 MIT Prüfung (Wird sicher gestoppt)
        new KeyExchange()
            .setAttackType(AttackType.ATTACK_2)
            .setValidationMode(ValidationMode.VALIDATE_PUBLIC_VALUES)
            .run();
    }
}
