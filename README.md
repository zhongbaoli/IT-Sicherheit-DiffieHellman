# IT Sicherheit DiffieHellman
 Gruppe mit Krushali Patel, Alexander Flach, Julian Kohlert und Zhong Bao Li

## Projekt Setup zum Ausprobieren
### Grundvoraussetzungen
* JDK (25.0.5.1) installieren
* Python (3.15.2) installieren
* Befehl ausführen: py -m pip install jupyter
* Wenn VSCode verwendet wird: Jupyter Extension von Microsoft installieren
* IJava herunterladen und py install.py im Ordner ausführen
* Kernel auswählen: Jupyter Kernel -> Java


## Teilaufgabe 3: Parameter- und Werteprüfung (Alexander)

Eine sichere Implementierung des Diffie-Hellman Schlüsselaustauschs erfordert eine Überprüfung aller an der mathematischen Berechnung beteiligten Werte. Werden initiale Parameter falsch gewählt oder öffentliche Schlüssel ungeprüft verwendet, bricht die mathematische Sicherheit, die durch das Diskrete-Logarithmus-Problem erzeugt wird.

Dieser Abschnitt analysiert die konkreten Schwachstellen im ungeprüften Austausch, definiert eine systematische Prüfliste und vergleicht das Systemverhalten vor und nach der Absicherung.

### 1. Ursachenanalyse fehlender SicHErheitsprüfungen

Die in den Demonstrationen aufgezeigten Angriffe basieren auf der unterlassenen Prüfung der Parameter des Schlüsselaustauschs. Vor der Implementierung der Gegenmaßnahmen muss exakt bestimmt werden, an welcher Stelle welche mathematische Eigenschaft ungeprüft bleibt.

#### A. Fehlende Parameterprüfung bei $p$ und $g$ (Angriff 1)
Beim initialen Aufbau des Schlüsselaustauschs einigen sich Alice und Bob auf den Modulus $p$ sowie den Generator $g$. Wird dieser Schritt nicht abgesichert, treten zwei wesentliche Schwachstellen auf:
* **Zusammengesetzter Modulus $p$:** Fehlt der Primzahltest (isProbablePrime), kann ein Angreifer eine zusammengesetzte Zahl $p = p_1 \cdot p_2$ einschleusen. Der Restklassenring $\mathbb{Z}_p^*$ zerfällt dadurch in kleinere Faktoren ringisomorph zu $\mathbb{Z}_{p_1}^* \times \mathbb{Z}_{p_2}^*$, was die Berechnung des diskreten Logarithmus mittels des Pohlig-Hellman-Algorithmus trivialisiert.
* **Ungültiger Generator $g$:** Fehlt die Prüfung des Wertebereichs $1 < g < p - 1$, können triviale Generatoren wie $g = 0$, $g = 1$ oder $g = p - 1$ eingebracht werden. Dies führt dazu, dass der erzeugte öffentliche Wert $g^x \bmod p$ nur noch die Elemente $0$, $1$ oder $p-1$ annehmen kann.

#### B. Ungeprüfte Übernahme empfangener öffentlicher Schlüssel $Y$ (Angriff 2)
Nach dem Austausch der öffentlichen Werte berechnet Bob das gemeinsame Geheimnis gemäß $K = Y^b \bmod p$, wobei $Y$ den von Alice empfangenen Wert darstellt. Wird $Y$ vor der Potenzierung nicht validiert, ist das System verwundbar für Small Subgroup Attacks:

* **Untergruppeneinspeisung:** Ein Angreifer wählt als öffentlichen Wert ein Element $Y$, das eine sehr kleine zyklische Untergruppe $U \subset \mathbb{Z}_p^*$ erzeugt (z. B. der Ordnung $q = 1$ oder $q = 2$).
* **Auswirkung auf $K$:** Da für jedes Element der Untergruppe $Y^q \equiv 1 \pmod p$ gilt, nimmt das berechnete gemeinsame Geheimnis $K = Y^b \bmod p$ unabhängig von Bobs privatem Schlüssel $b$ nur extrem wenige Werte an (z. B. $K = 1$ bei $Y = 1$ oder $K \in \{1, p-1\}$ bei $Y = p-1$). Der Angreifer kann das Geheimnis somit ohne nennenswerten Rechenaufwand bestimmen.

#### C. Wiederverwendung statischer privater Schlüssel $x$ (Angriff 3)
Die Wiederverwendung desselben privaten Schlüssels $b$ über mehrere Sitzungen hinweg in Kombination mit einer fehlenden Untergruppenprüfung ermöglicht die schrittweise Rekonstruktion des Schlüssels:

* **Informationsextraktion mittels Untergruppen:** Sendet der Angreifer in aufeinanderfolgenden Sitzungen gezielt öffentliche Werte $Y_i$, die kleinen Untergruppen der Ordnungen $q_1, q_2, \dots, q_k$ angehören, kann er aus den jeweils resultierenden Sitzungsschlüsseln die Werte $b \bmod q_i$ exakt bestimmen.
* **CRT-Rekonstruktion:** Durch Anwendung des Chinesischen Restsatzes (CRT) verbindet der Angreifer die modularen Kongruenzen $b \equiv r_i \pmod{q_i}$ zu einem linearen Gleichungssystem und berechnet den vollständigen privaten Schlüssel $b$.

### 2. Systematische Prüfliste für Diffie-Hellman-Komponenten
Aus der Ursachenanalyse leitet sich eine dreiteilige Prüfliste ab, die alle Systemkomponenten vor der Verwendung im kryptographischen Protokoll durchlaufen müssen.

#### A. Prüfkriterien für Systemparameter ($p$ und $g$)
Die öffentlichen Gruppenparameter definieren den mathematischen Raum des Protokolls und müssen vor Beginn jeder Berechnung geprüft werden:

* **Primzahleigenschaft des Modulus $p$:** Der Modulus muss mittels p.isProbablePrime(100) auf Primzahlzugehörigkeit getestet werden. Bei einer Fehlschlagswahrscheinlichkeit von unter $2^{-100}$ wird sichergestellt, dass die mathematische Gruppenstruktur intakt bleibt.
* **Bitlänge des Modulus $p$:** Die Bitlänge von $p$ muss mindestens den Sicherheitsanforderungen entsprechen (p.bitLength() >= MIN_BIT_LENGTH). Für Test- und Übungsszenarien gilt $\ge 512$ Bit, für produktive Systeme $\ge 2048$ Bit.
* **Wertebereich des Generators $g$:** Der Generator muss im Bereich $1 < g < p - 1$ liegen, um triviale Werte zu verhindern.

#### B. Prüfkriterien für empfangene öffentliche Schlüssel ($Y$)
Empfangene Werte der Gegenstelle dürfen nicht ungeprüft verarbeitet werden:

* **Nicht-Null-Prüfung:** Das Objekt $Y$ darf nicht null sein.
* **Reichweiten- & Untergruppensperre:** Es muss $1 < Y < p - 1$ gelten.
  * Ausschluss von $Y \le 1$ verhindert die Reduktion auf das triviale Geheimnis $K = 1$.
  * Ausschluss von $Y \ge p - 1$ schützt vor Untergruppen der Ordnung 2 mit $K \in \{1, p-1\}$.
  * Ausschluss von $Y \ge p$ verhindert Werte außerhalb des gültigen Restklassenrings.

#### C. Prüfkriterien für eigene private Schlüssel ($x$)
Auch der lokal erzeugte private Schlüssel unterliegt Qualitätsanforderungen:

* **Reichweitencheck:** Der private Schlüssel muss im Intervall $1 < x < p - 1$ liegen. Werte von $x \le 1$ erzeugen triviale öffentliche Schlüssel ($g^0 = 1$ bzw. $g^1 = g$). Exponenten mit $x \ge p$ bieten aufgrund der Periodizität modulo $p-1$ keinen Sicherheitsgewinn und verlangsamen die Berechnung.
* **Kryptographische Entropie:** Der Schlüssel muss zwingend über SecureRandom mit ausreichender Bitlänge ($\ge 256$ Bit) erzeugt werden.
* **Ephemerität (Perfect Forward Secrecy):** Für jede Sitzung muss ein neuer Schlüssel $x$ generiert werden, um Angriffe mittels Chinesischem Restsatz zu unterbinden.

### 3. Technische Umsetzung in Java (Validator.java)

Die Validierungslogik ist in `Validator.java` umgesetzt:

* Die Methode `validateParameters(p, g)` prüft die Gruppenparameter $p$ und $g$ auf die genannten Eigenschaften.
* Die Methode `validatePublicValue(Y, p, participant)` prüft den übermittelten öffentlichen Wert des anderen Teilnehmers vor dem Verwenden auf die genannten Eigenschaften.
* Die Methode `validatePrivateKey(k, p, participant)` prüft den gewählten privaten Schlüssel des Teilnehmers auf die genannten Eigenschaften.

Bei Verletzungen der definierten Regeln wird eine `SecurityException` ausgelöst.

Zu Demonstrationszwecken lässt sich der Validierungsmodus für jeden Austausch einstellen:
* `ValidationMode.NONE`: Kein Wert wird geprüft.
* `ValidationMode.VALIDATE`: Ruft beim Start `validateParameters(p, g)` und `validatePrivateKey(k, p, participant)` und nach dem Erhalt des öffentlichen Werts des anderen Teilnehmers `validatePublicValue(Y, p, participant)` auf.

### 4. Vorher/Nachher-Vergleich und Verhalten im System

table TBD