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


        // Aufruf der ausgelagerten Simulation für Angriff 3
        simulateAttack3CRT();
    }

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

            // 4. ANGRIFF: MANIPULATION DER ÖFFENTLICHEN WERTE
            BigInteger aliceReceivedPublicKey = bobPublicKey;
            BigInteger bobReceivedPublicKey = alicePublicKey;

            //@Krushali
            if (attackType == AttackType.ATTACK_1 || attackType == AttackType.ATTACK_3 || attackType == AttackType.ALL) {
                
                // Wenn ein spezieller Wert gesetzt wurde, nimm diesen. Sonst standardmäßig p-1.
                BigInteger maliciousValue = (injectedAttackerValue != null) 
                                            ? injectedAttackerValue 
                                            : activeParameters.modulus.subtract(BigInteger.ONE);
                
                // Angreifer fängt den Wert ab und sendet seinen manipulierten Wert an Bob
                bobReceivedPublicKey = maliciousValue;
                
                // TIPP: Damit Alice und Bob denselben falschen Schlüssel berechnen 
                // und die Kommunikation nicht sofort abbricht, sollte der Angreifer 
                // auch Alice den falschen Wert unterjubeln:
                aliceReceivedPublicKey = maliciousValue;
                
                System.out.println("\n[ANGRIFF] Angreifer fängt den Schlüsselaustausch ab!");
                System.out.println(" [ANGRIFF] Er sendet stattdessen " + maliciousValue + " an die Parteien.");
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
                System.out.println("WARNUNG: Angriff 2 war erfolgreich! Das Geheimnis K wurde auf den festen Wert " + aliceRawSecret + " gezwungen!");
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

    public static void simulateAttack3CRT() {
        System.out.println("\n=======================================================");
        System.out.println("=== DEMO: ANGRIFF 3 (Statischer Schlüssel + CRT) ===");
        System.out.println("=======================================================");
        
        System.out.println("\n--- SITZUNG 1 (Angreifer sendet 30, erzeugt 2er Gruppe) ---");
        KeyExchange session1 = new KeyExchange()
            .setAttackType(AttackType.ATTACK_3)
            .setValidationMode(ValidationMode.NONE)
            .setInjectedAttackerValue(BigInteger.valueOf(30)); 
        session1.run();
        // Erkenntnis aus Sitzung 1
        int rest2 = 1;

        System.out.println("\n--- SITZUNG 2 (Angreifer sendet 25, erzeugt 3er Gruppe) ---");
        KeyExchange session2 = new KeyExchange()
            .setAttackType(AttackType.ATTACK_3)
            .setValidationMode(ValidationMode.NONE)
            .setInjectedAttackerValue(BigInteger.valueOf(25)); 
        session2.run();
        // Erkenntnis aus Sitzung 2
        int rest3 = 1;

        System.out.println("\n--- SITZUNG 3 (Angreifer sendet 16, erzeugt 5er Gruppe) ---");
        KeyExchange session3 = new KeyExchange()
            .setAttackType(AttackType.ATTACK_3)
            .setValidationMode(ValidationMode.NONE)
            .setInjectedAttackerValue(BigInteger.valueOf(16)); 
        session3.run();
        // Erkenntnis aus Sitzung 3
        int rest5 = 3;

        System.out.println("\n [ANGRIFF 3 - FINALE] Chinesischer Restsatz wird angewendet...");
        System.out.println("Angreifer weiß nun:");
        System.out.println("Bob's Private Key % 2 = " + rest2);
        System.out.println("Bob's Private Key % 3 = " + rest3);
        System.out.println("Bob's Private Key % 5 = " + rest5);
        
        // Der Angreifer löst das Gleichungssystem
        for (int i = 1; i < 31; i++) {
            if (i % 2 == rest2 && i % 3 == rest3 && i % 5 == rest5) {
                System.out.println("==> BINGO! Der Angreifer hat Bobs statischen privaten Schlüssel berechnet: " + i);
                break;
            }
        }
    }

}
