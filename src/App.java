import java.math.BigInteger;
import java.util.Scanner;

public class App {
    public static void main(String[] args) throws Exception {
    Scanner scanner = new Scanner(System.in);

    Parameters parameters = new Parameters(23, 11, 2);

    System.out.println("Enter privateKey for Alice:");
    int userInputPkAlice = scanner.nextInt();
    
    System.out.println("Enter privateKey for Bob:");
    int userInputPkBob = scanner.nextInt();




    Participant alice = new Participant(parameters, BigInteger.valueOf(userInputPkAlice));

    Participant bob = new Participant(parameters, BigInteger.valueOf(userInputPkBob));

    //compute publicKey
    BigInteger publicAlice = alice.getPublicKey();
    BigInteger publicBob = bob.getPublicKey();
    
    //compute sharedSecret
    BigInteger secretAlice = alice.computeSharedSecret(publicBob);
    BigInteger secretBob = bob.computeSharedSecret(publicAlice);

    System.out.println("Alice Geheimnis: " + secretAlice);
    System.out.println("Bob Geheimnis: " + secretBob);

    System.out.println("Identisch: " + secretAlice.equals(secretBob));
    }
}
