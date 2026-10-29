import java.math.BigInteger;
import java.util.Scanner;

public class App {
    public static void main(String[] args) throws Exception {
    Scanner scanner = new Scanner(System.in);
    
    // Beispiel Parameter (können für currentParameters verwendet werden)
    Parameters bigParameters = new Parameters(BigInteger.valueOf(2), new BigInteger( "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" + "F001007573752636664F40C8300000000000000000000000" + "000000000000000000000000000000000000000000000000" + "000000000000000000000000000000000000000000000000" + "000000000000000000000000000000000000000000000000" + "000000000000000000000000000000000000000000000000" + "000000000000000000000000000000000000000000000000" + "FFFFFFFFFFFFFFFF", 16));
    Parameters smallParameters = new Parameters(3, 30);


    System.out.println("==================================================");
    System.out.println("   INTERAKTIVER DIFFIE-HELLMAN SCHLÜSSELAUSTAUSCH   ");
    System.out.println("==================================================\n");

    // ---------------------------------------------------------------------
    // SCHRITT 1: Parameter festlegen & validieren
    // ---------------------------------------------------------------------
    System.out.println("--- SCHRITT 1: Parameter festlegen & validieren ---");


    Parameters currentParameters = smallParameters; // Aktuell verwendete Parameter (kann auf bigParameters geändert werden)

    BigInteger p = currentParameters.modulus;
    BigInteger g = currentParameters.generator;

    try {
            Validator.validateParameters(p, g);
        } catch (SecurityException e) {
            System.err.println(e.getMessage());
            System.out.println("Abbruch wegen ungültiger Gruppenparameter!");
            return;
        }
    
    System.out.println();


    // ---------------------------------------------------------------------
    // SCHRITT 2: Nutzereingabe der privaten Schlüssel (a und b)
    // ---------------------------------------------------------------------
    System.out.println("--- SCHRITT 2: Eingabe der geheimen privaten Schlüssel ---");
    System.out.println("Geben Sie eine Zahl für Alices privaten Schlüssel (a) ein oder drücken Sie [ENTER] für eine Zufallszahl:");
    String inputA = scanner.nextLine().trim();
    BigInteger privateKeyAlice;
    if (inputA.isEmpty()) {
        privateKeyAlice = new BigInteger(256, new java.security.SecureRandom());
        System.out.println("-> Zufälliger privater Schlüssel für Alice generiert: " + privateKeyAlice.toString(16).substring(0, 16) + "...");
    } else {
        privateKeyAlice = new BigInteger(inputA);
        System.out.println("-> Alices privater Schlüssel gesetzt.");
    }

    System.out.println("\nGeben Sie eine Zahl für Bobs privaten Schlüssel (b) ein oder drücken Sie [ENTER] für eine Zufallszahl:");
    String inputB = scanner.nextLine().trim();
    BigInteger privateKeyBob;
    if (inputB.isEmpty()) {
        privateKeyBob = new BigInteger(256, new java.security.SecureRandom());
        System.out.println("-> Zufälliger privater Schlüssel für Bob generiert: " + privateKeyBob.toString(16).substring(0, 16) + "...");
    } else {
        privateKeyBob = new BigInteger(inputB);
        System.out.println("-> Bobs privater Schlüssel gesetzt.");
    }


    Participant alice = new Participant(currentParameters, privateKeyAlice);

    Participant bob = new Participant(currentParameters, privateKeyBob);

    //compute publicKey
    BigInteger publicKeyAlice = alice.getPublicKey();
    BigInteger publicKeyBob = bob.getPublicKey();
    
    System.out.println("\n--- Öffentliche Schlüssel berechnet ---");

    // ---------------------------------------------------------------------
    // SCHRITT 3: Validierung der berechneten öffentlichen Schlüssel
    // ---------------------------------------------------------------------
    System.out.println("--- SCHRITT 3: Validierung der öffentlichen Werte ---");
    try {
        System.out.println("Validiere Alices öffentlichen Wert A...");
        Validator.validatePublicValue(publicKeyAlice, p);
        
        System.out.println("Validiere Bobs öffentlichen Wert B...");
        Validator.validatePublicValue(publicKeyBob, p);
    } catch (SecurityException e) {
        System.err.println(e.getMessage());
        System.out.println("Abbruch: Die berechneten öffentlichen Werte bestehen die Validierung nicht!");
        return;
    }

    System.out.println();
    




    // ---------------------------------------------------------------------
    // SCHRITT 4: Übertragung der Schlüssel (Warten auf ENTER)
    // ---------------------------------------------------------------------
    System.out.println("--- SCHRITT 4: Übertragung über das (unsichere) Netzwerk ---");
    System.out.println(">>> Drücken Sie [ENTER], um die öffentlichen Werte (A -> Bob, B -> Alice) zu übertragen...");
    scanner.nextLine();

    System.out.println("-> Übertragung läuft...");
    System.out.println("   [A] wird an Bob gesendet.");
    System.out.println("   [B] wird an Alice gesendet.");
    System.out.println("-> Übertragung erfolgreich abgeschlossen!\n");

    System.out.println("Alice schickt Public Key " + publicKeyAlice + " an Bob");
    System.out.println("Bob schickt Public Key " + publicKeyBob + " an Alice");

    // ---------------------------------------------------------------------
    // SCHRITT 5: Berechnung des gemeinsamen Geheimnisses & Sitzungsschlüssels
    // ---------------------------------------------------------------------
    System.out.println("--- SCHRITT 5: Berechnung des gemeinsamen Geheimnisses ---");

    //compute sharedSecret
    BigInteger sharedSecretAlice = alice.computeSharedSecret(publicKeyBob);
    BigInteger sharedSecretBob = bob.computeSharedSecret(publicKeyAlice);

    System.out.println("Alice berechnet Geheimnis: " + sharedSecretAlice);
    System.out.println("Bob berechnet Geheimnis: " + sharedSecretBob);

    System.out.println();

    boolean match = sharedSecretAlice.equals(sharedSecretBob);
    System.out.println("\n==> " + (match ? "Die Schlüssel stimmen überein!" : "Die Schlüssel stimmen NICHT überein!"));
    System.out.println("==================================================");

    System.out.println();

    currentParameters.printGroupAndSubgroup(p, g);
    }
}