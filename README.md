# IT Sicherheit DiffieHellman
 Gruppe mit Krushali Patel, Alexander Flach, Julian Kohlert und Zhong Bao Li




## Teilaufgabe 3: Parameter- und Werteprüfung (Alexander)

### 1. Aufgabenstellung
Entwicklung einer Prüfliste für Diffie-Hellman-Parameter und empfangene öffentliche Werte, um Angriffe (wie Small Subgroup Attacks) abzuwehren und mathematische Manipulationen sicher zu verhindern.

---

### 2. Prüfkriterien

#### A. Systemparameter (p und g)
* **Modulus p**: 
  * *Prüfung:* Primzahlcheck (isProbablePrime) & Bitlängenprüfung (>= 512 Bit).
  * *Grund:* Zusammengesetzte Zahlen zerstören die Gruppenstruktur und vereinfachen die Schlüsselerrechnung (Angriff 1).
* **Generator g**:
  * *Prüfung:* 1 < g < p - 1.
  * *Grund:* Schließt triviale Werte (0, 1, p-1) aus.

#### B. Empfangene öffentliche Schlüssel (Y)
* **Reichweiten- & Untergruppenschutz**: 1 < Y < p - 1.
  * *Grund:* 
    * Y <= 1: Erzwingt das triviale Geheimnis K = 1.
    * Y >= p - 1: Kompromittiert das Geheimnis auf K in {1, p-1} (Angriff 2).
    * Y >= p: Liegt außerhalb des Restklassenrings.

---

### 3. Umsetzung im Code (Validator.java)

Die Validierungslogik ist in `Validator.java` umgesetzt:

* `validateParameters(p, g)`: Prüft p auf Primzahleigenschaft/Bitlänge und g auf den zulässigen Bereich.
* `validatePublicValue(Y, p)`: Prüft empfangene Schlüssel (1 < Y < p - 1), bevor K = Y^x mod p berechnet wird. Wirft bei Fehlern eine `SecurityException`.

#### Einbindung in KeyExchange.java
* `ValidationMode.NONE` (Vorher): Angriffe laufen unbemerkt durch.
* `ValidationMode.VALIDATE_PARAMETERS` und `ValidationMode.VALIDATE_PUBLIC_VALUE` (Nachher): Stoppt Angriffe sicher vor der Verrechnung.
