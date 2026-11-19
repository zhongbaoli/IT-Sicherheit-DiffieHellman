# 📋 Vollständige Projekt-Checkliste: Diffie-Hellman Schlüsselaustausch

> **Modul:** IT-Sicherheit Gruppenaufgabe (WS 2026 / Prof. Dr. Christiane Weis)  
> **Thema:** Aufgabe 3 – Diffie-Hellman-Schlüsselaustausch  
> **Team:** Zhong, Krushali, Alexander, Julian  
> **Status:** Machbarkeitsnachweis eingereicht `[x]` | Endabgabe in Vorbereitung `[ ]`

---

## 🚀 1. Bereits absolvierte Meilensteine
- [x] **Themenzuteilung & Teambildung:** Aufgabe 3 (Diffie-Hellman) zugewiesen bekommen.
- [x] **Aufgabenverteilung im Team:** Zuständigkeiten definiert (Zhong, Krushali, Alexander, Julian).
- [x] **Abgabe Machbarkeitsnachweis (bereits eingereicht):**
  - [x] Angreifermodell in einem prägnanten Satz beschrieben.
  - [x] Lauffähigkeit der Demo nachgewiesen (Screenshots / Mitschnitte beigefügt).
  - [x] Offene / hängende Teilaufgaben benannt.
  - [x] Geschätzter Restaufwand pro Person dokumentiert.

---

## 🧩 2. Inhaltliche Aufgabenstellung (5-Schritte-Schema aus Aufgabenpool.pdf)

### Schritt 1: Grundlagen, Parameter & Angreifermodell (Zuständig: Zhong)
- [ ] **Funktionsweise von Diffie-Hellman (DH) erklären:**
  - [ ] Prinzip der mathematischen Einwegfunktion (Diskretes-Logarithmus-Problem) verständlich darstellen.
  - [ ] Ablauf der Schlüsseleinigung über einen offenen, unsicheren Kanal erläutern.
- [ ] **Anforderungen an die öffentlichen Systemparameter definieren:**
  - [ ] **Modulus $p$:** Anforderungen erklären (große Primzahl, ausreichend Bitlänge z. B. $\ge 2048$ Bit bzw. $\ge 512$ Bit für Tests).
  - [ ] **Generator $g$:** Anforderungen definieren ($1 < g < p - 1$).
  - [ ] **Ordnung der erzeugten Gruppe:** Gruppenstruktur ($\mathbb{Z}_p^*$) und zyklische Untergruppen erklären.
- [ ] **Angreifermodell präzise benennen:**
  - [ ] Fähigkeiten des Angreifers im Basisszenario definieren (passiver Lauscher, Dolev-Yao-Kanalmodell, volle Kontrolle über den Netzverkehr ohne Schreib-/Manipulationsrechte beim Standard-DH).

### Schritt 2: Basis-Implementierung & KDF (Zuständig: Zhong)
- [ ] **DH-Protokollablauf zwischen zwei Parteien (Alice & Bob) implementieren:**
  - [ ] Generierung der privaten Schlüssel ($a, b$) und öffentlichen Schlüssel ($A = g^a mod p$, $B = g^b mod p$).
  - [ ] Nachrichtenaustausch simulieren.
- [ ] **Kryptographische Schlüsselableitung (KDF) umsetzen:**
  - [ ] Rohes Geheimnis $K = g^{ab} mod p$ berechnen.
  - [ ] KDF (z. B. via SHA-256 / HKDF) auf $K$ anwenden, um den echten symmetrischen Sitzungsschlüssel abzuleiten.
- [ ] **Wertesichtbarkeit im System herausarbeiten:**
  - [ ] Klar dokumentieren/visualisieren: Welche Werte werden über den Kanal übertragen ($p, g, A, B$)?
  - [ ] Klar dokumentieren/visualisieren: Welche Werte verlassen das jeweilige System **niemals** ($a, b, K$, Sitzungsschlüssel)?
- [ ] **Begründung für die KDF liefern:**
  - [ ] Mathematisch/kryptographisch begründen, warum das rohe Rechenergebnis $K$ nicht direkt als symmetrischer Schlüssel (z. B. für AES) genutzt werden darf (ungleichmäßige Bitverteilung, mathematische Struktur, algebraische Abhängigkeiten).

### Schritt 3: Demonstration von Fehlgebrauch & Angriffen (Zuständig: Krushali)
*Für jeden der 3 Fälle muss gezeigt werden: Was erfährt der Angreifer über den Schlüssel und wie hoch ist sein Aufwand?*

- [ ] **Angriff 1: Untergeschobene oder ungeeignete Gruppenparameter**
  - [ ] Szenario implementieren (z. B. zusammengesetztes $p$ oder ungeeigneter Generator $g$).
  - [ ] Demonstration: Einbruch der mathematischen Schwerheit (Einfaches Diskretes Logarithmus Problem).
  - [ ] Analyse: Exakt quantifizieren, was der Angreifer erfährt und wie gering sein Rechenaufwand ist.
- [ ] **Angriff 2: Öffentlicher Wert in einer kleinen Untergruppe (Small Subgroup Attack)**
  - [ ] Szenario implementieren: Angreifer schiebt $Y$ ein, das nur eine kleine Untergruppe der Ordnung $q$ erzeugt (z. B. $Y \in \{1, p-1\}$).
  - [ ] Demonstration: Das berechnete Geheimnis $K$ nimmt nur sehr wenige mögliche Werte an.
  - [ ] Analyse: Gewinn des Angreifers (Reduktion des Schlüsselraums auf wenige Bits) und Aufwandsanalyse zeigen.
- [ ] **Angriff 3: Wiederverwendung statischer Schlüsselanteile (Static DH + CRT)**
  - [ ] Szenario implementieren: Bob verwendet denselben privaten Schlüssel $b$ über mehrere Sitzungen hinweg; Angreifer schiebt gezielt Elemente verschiedener kleiner Untergruppen ein.
  - [ ] Demonstration: Angreifer sammelt Teilergebnisse $b mod q_i$ und wendet den Chinesischen Restsatz (CRT) an.
  - [ ] Analyse: Vollständige Rekonstruktion von Bobs privatem Schlüssel $b$ vorführen und Aufwand benennen.

### Schritt 4: Fehleranalyse, Prüfliste & Implementierung (Zuständig: Alexander)
- [ ] **Ursachenanalyse:**
  - [ ] Für jeden der 3 Angriffe präzise analysieren: Welche Prüfung hat an welcher konkreten Stelle im Code/Protokoll gefehlt?
- [ ] **Vollständige Prüfliste (Validator-Spezifikation) erstellen:**
  - [ ] Kriterien für Systemparameter ($p, g$): Primzahltest, Bitlänge, Wertebereich $1 < g < p-1$.
  - [ ] Kriterien für empfangene öffentliche Schlüssel ($Y$): Reichweitencheck $1 < Y < p-1$, Prüfung auf kleine Untergruppen.
  - [ ] Kriterien für eigene private Schlüssel ($x$): $1 < x < p-1$, kryptographisch sichere Zufallserzeugung (`SecureRandom`).
- [ ] **Validator in Java implementieren (`Validator.java` / `DHParameterValidator.java`):**
  - [ ] Prüffunktionen schreiben und Exceptions bei Fehlern werfen.
- [ ] **Vorher/Nachher-Vergleich im Code durchführen:**
  - [ ] Verhalten bei `ValidationMode.NONE` (Angriffe gelingen unbemerkt).
  - [ ] Verhalten bei `ValidationMode.STRICT` (Angriffe werden sofort abgefangen).

### Schritt 5: Praxisbezug, Einordnung & Protokolle (Zuständig: Julian)
- [ ] **Lösung in realen Protokollen aufzeigen:**
  - [ ] Erläutern, wie Protokolle wie TLS 1.3, SSH oder IPsec (IKEv2) Parameter- und Werteprüfungen umsetzen (z. B. Einsatz vordefinierter MODP-Gruppen nach RFC 3526 oder Elliptischer Kurven ECDHE).
- [ ] **Schutzumfang der Parameterprüfung abgrenzen:**
  - [ ] Präzise einordnen: Wogegen schützt die Parameterprüfung (mathematische Manipulationen, Small Subgroup Attacks)?
  - [ ] Wogegen schützt sie **nicht** (z. B. Man-in-the-Middle-Angriffe ohne Authentifizierung)?
- [ ] **Unterschied zwischen authentifiziertem und unauthentifiziertem Austausch:**
  - [ ] Man-in-the-Middle-Szenario (MitM) erklären.
  - [ ] Aufzeigen, wie Zertifikate / digitale Signaturen DH authentifizieren.
- [ ] **Forward Secrecy (Perfect Forward Secrecy - PFS) erklären:**
  - [ ] Unterschied zwischen statischem DH und ephemerem DH (DHE / ECDHE) herausarbeiten.
  - [ ] Begründen, warum ephemere Schlüssel die Vergangenheit vor nachträglicher Entschlüsselung schützen.
- [ ] **Restrisiken benennen:**
  - [ ] Klar formulieren, welche Risiken auch bei vollständiger Parameterprüfung und DHE offen bleiben (z. B. Kompromittierung des Endpunkts, Implementierungsfehler, DoS-Angriffe).

---

## 📄 3. Dokumente & Abgabe-Artefakte (gemäß Infos_Gruppenaufgabe_Abgaben.txt)

### A. Ausarbeitung / Endbericht (Ausarbeitung der Lösung)
- [ ] **Formalia:**
  - [ ] Exakt 4 Seiten Hauptteil im **IEEE Conference Template**.
  - [ ] Seite 5 reserviert für Referenzen und Angaben zu Hilfsmitteln (z. B. KI-Tools wie ChatGPT/Gemini).
  - [ ] Anhang (unbegrenzt) für Bilder, Diagramme, Code-Snippets und Screenshots.
- [ ] **Inhalte der Ausarbeitung:**
  - [ ] Transparente Aufteilung der Unteraufgaben im Team (Zhong, Krushali, Alexander, Julian).
  - [ ] Vollständige Dokumentation der 5 Schritte aus dem Aufgabenpool.
  - [ ] Ausführliche Angaben zu den verwendeten Hilfsmitteln.

### B. Steckbrief (1 Seite PDF)
- [ ] **Informationsteil:**
  - [ ] Übersichtliche Zusammenfassung des Themengebiets Diffie-Hellman gemäß Vorlage.
  - [ ] Kernkonzepte, Angriffe, Schutzmaßnahmen, Kosten & Trade-Offs (z. B. DHE vs. Statisch).
- [ ] **Publikumsfrage:**
  - [ ] 1 Multiple-Choice-Frage für die Präsentation einbauen.
  - [ ] **4 Antwortmöglichkeiten (A, B, C, D)** formulieren (1 richtige Lösung, 3 plausible Distraktoren).
  - [ ] Musterlösung mit kurzer Erklärung/Begründung vorbereiten.

### C. Artefakte & Beitragszuordnung (ZIP-Archiv)
- [ ] **Quellcode & Programme:**
  - [ ] Kompilierbare Java-Dateien (`KeyExchange.java`, `Validator.java`, `Participant.java`, etc.).
  - [ ] Ausführbares Jupyter Notebook (`.ipynb`) zur übersichtlichen Demonstration aller Schritte & Angriffe.
- [ ] **Beitragszuordnung:**
  - [ ] Schriftliche Übersicht im ZIP/Bericht: Welcher Code, welche Konsoleneingaben und welche Textabschnitte wurden von welchem Gruppenmitglied erstellt?

---

## 🎤 4. Präsentation & Vorstellung

- [ ] **Präsentationsmedien vorbereiten:**
  - [ ] Folien (z. B. PowerPoint / PDF) oder Notebook-Live-Demo strukturiert aufbauen.
  - [ ] Einleitung mit kurzer Wiederholung der relevanten Vorlesungsinhalte.
- [ ] **Praktische Demonstration (Live-Demo):**
  - [ ] Reibungslose Vorführung der 3 Angriffe im Jupyter Notebook sicherstellen.
  - [ ] Live-Nachweis der Funktionsweise des Validators (`NONE` vs. `STRICT`).
- [ ] **Publikumsfrage (2–3 Minuten Slot):**
  - [ ] Folie mit der Multiple-Choice-Frage (4 Optionen A–D) einbinden.
  - [ ] Abstimmung der Zuhörer moderieren und die Auflösung verständlich erklären.
- [ ] **Vorbereitung auf die Fragerunde (Kolloquium):**
  - [ ] **Variationsfragen durchgehen:**
    - *"Was wäre, wenn der Angreifer $Y = 0$ oder $Y = p$ wählt?"*
    - *"Wie würde sich das Verfahren verändern, wenn wir auf Elliptische Kurven (ECDHE) wechseln?"*
    - *"Was passiert, wenn der private Schlüssel $x > p$ gewählt wird?"*
  - [ ] **Erklärfragen zu Fachbegriffen vorbereiten:**
    - Erklärungen für Begriffe wie *Diskretes-Logarithmus-Problem*, *Small Subgroup Attack*, *Chinesischer Restsatz (CRT)*, *Perfect Forward Secrecy (PFS)*, *KDF*, *MODP-Gruppen*.

---

## 📌 5. Zusammenfassende Aufgabenverteilung & Verantwortlichkeiten

| Teammitglied | Hauptverantwortung (Inhalt) | Code / Artefakte | Bericht & Präsentation |
| :--- | :--- | :--- | :--- |
| **Zhong** | Schritt 1 & 2: DH-Grundlagen, Parameter, Angreifermodell, KDF | Basis-DH & KDF in Java | Abschnitt Grundlagen & Basisprogramm |
| **Krushali** | Schritt 3: Angriffe 1, 2 & 3 (Parameter, Subgroups, CRT) | Angriffsszenarien in Java | Abschnitt Angriffsdemonstrationen |
| **Alexander** | Schritt 4: Ursachenanalyse, Prüfliste & Validator | `Validator.java` & Vorher/Nachher-Demo | Abschnitt Prüfliste & Validierung |
| **Julian** | Schritt 5: Reale Protokolle, MitM, PFS & Restrisiken | Integration & Protokoll-Einordnung | Abschnitt Protokolle, PFS & Fazit |

---

> **Nächster Schritt:** Alle Punkte nacheinander abhaken und die Ergebnisse im Jupyter Notebook sowie in der 4-seitigen IEEE-Ausarbeitung zusammenführen!
