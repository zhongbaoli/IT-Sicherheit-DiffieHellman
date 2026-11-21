package dh;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

/**
 * Prüfliste für Diffie-Hellman-Parameter und öffentliche Werte
 * 
 * Diese Klasse stellt Validierungsfunktionen bereit, um unsichere Gruppenparameter
 * sowie manipulierte öffentliche Schlüssel (z. B. Small Subgroup Attacks) abzufangen.
 */

public class Validator {

    // Empfohlene Mindest-Bitlänge für Modulus p
    public static final int MIN_BIT_LENGTH = 512;  // 512 Bit ist heutzutage ein Minimum, 2048 Bit oder mehr wird empfohlen.

    public static final Set<BigInteger> usedPrivateKeys = new HashSet<>();

    /**
     * 1. Prüfung der öffentlichen Gruppenparameter (p und g).
     * 
     * @param p Modulus (Primzahl)
     * @param g Generator (Basis)
     * @throws SecurityException wenn Parameter ungültig oder unsicher sind
     */
    public static void validateParameters(BigInteger p, BigInteger g) throws SecurityException {
        System.out.println("\n[VALIDIERUNG]");
        System.out.println("Starte Validierung der Gruppenparameter (p, g)...");
        System.out.println("Modulus p = " + p);
        System.out.println("Generator g = " + g);

        // 1.1 Bitlänge von p prüfen
        if (p.bitLength() < MIN_BIT_LENGTH) {
            throw new SecurityException("-> PARAMETER-FEHLER: Modulus p ist zu kurz (" 
                    + p.bitLength() + " Bits). Minimum ist " + MIN_BIT_LENGTH + " Bits!");
        }

        // 1.2 Primzahlprüfung für p
        if (!p.isProbablePrime(100)) {
            throw new SecurityException("-> PARAMETER-FEHLER: Modulus p ist keine Primzahl!");
        }

        // 1.3 Bereichsprüfung für Generator g (1 < g < p-1)
        if (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new SecurityException("-> PARAMETER-FEHLER: Generator g liegt außerhalb des erlaubten Bereichs (1 < g < p-1)!");
        }

        System.out.println("-> Gruppenparameter sind gültig.\n");
    }

    public static synchronized void validatePrivateKey(BigInteger privateKey, BigInteger p, String participant) throws SecurityException {
        System.out.println("\n[VALIDIERUNG]");
        System.out.println("Starte Validierung des privaten Schlüssels von " + participant + "...");
        if (privateKey == null) {
            throw new SecurityException("-> WERTE-FEHLER: Privater Schlüssel ist null!");
        }

        // Bereichsprüfung für privaten Schlüssel (1 < privateKey < p-1)
        if (privateKey.compareTo(BigInteger.ONE) <= 0 || privateKey.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new SecurityException("-> WERTE-FEHLER: Privater Schlüssel liegt außerhalb des erlaubten Bereichs (1 < privateKey < p-1)!");
        }

        if (usedPrivateKeys.contains(privateKey)) {
            throw new SecurityException("-> SCHLÜSSELWIEDERVERWENDUNG: Privater Schlüssel wurde bereits in einer früheren Sitzung verwendet!");
        }

        usedPrivateKeys.add(privateKey);

        System.out.println("-> Privater Schlüssel ist gültig.");
    }

    /**
     * 2. Prüfung empfangener öffentlicher Werte (Y = A bzw. B).
     * 
     * @param Y Empfangener öffentlicher Wert (g^x mod p)
     * @param p Modulus der Gruppe
     * @throws SecurityException wenn der Wert in einer gefährlichen Untergruppe liegt
     */
    public static void validatePublicValue(BigInteger Y, BigInteger p, String participant) throws SecurityException {
        System.out.println("\n[VALIDIERUNG]");
        System.out.println("Starte Validierung des öffentlichen Werts Y von " + participant + "...");
        if (Y == null) {
            throw new SecurityException("-> WERTE-FEHLER: Empfangener öffentlicher Wert Y ist null!");
        }

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);

        // Untergruppen- & Reichweitenprüfung: 1 < Y < p - 1
        if (Y.compareTo(BigInteger.ONE) <= 0) {
            throw new SecurityException("-> WERTE-FEHLER: Empfangener Wert Y <= 1! (Gefahr: Triviale Untergruppe mit Geheimnis K = 1)");
        }

        if (Y.compareTo(pMinusOne) >= 0) {
            throw new SecurityException("-> WERTE-FEHLER: Empfangener Wert Y >= p-1! (Gefahr: Kleine Untergruppe der Ordnung 2)");
        }

        System.out.println("-> Empfangener öffentlicher Wert Y von " + participant + " ist gültig.\n");
    }
}
