# RadarLume Desktop

Primo MVP diagnostico desktop, Java 21 e JavaFX. Raccoglie un inventario Android tramite ADB autorizzato e importa metadati di rete da catture PCAP/PCAPNG con TShark. Il nome provvisorio del progetto era Sentinel Desktop.

**Questo MVP non è un antivirus e non certifica l'assenza di malware o intercettazioni.** Non contiene ancora regole IOC, analisi APK o correlazione app/connessioni. Un errore di raccolta non viene trasformato in un risultato rassicurante.

## Funzionalità

- Discovery ADB con stati autorizzato, non autorizzato, offline e permessi mancanti.
- Selezione esplicita e consenso prima dell'inventario; nuova verifica dello stato al momento della lettura.
- Nomi dei pacchetti e classificazione sistema/utente, con filtro nella UI.
- Salvataggio volontario SQLite, caricamento dell'ultimo inventario e cancellazione dello storico con conferma.
- Importazione PCAP/PCAPNG: flussi TCP/UDP IPv4/IPv6 aggregati per direzione, conteggio pacchetti e byte dei frame.
- Operazioni fuori dal thread JavaFX, annullamento, timeout e limiti di output.

## Prerequisiti

- JDK **21**, con `JAVA_HOME` configurato. Maven Wrapper scarica Maven 3.9.11 al primo avvio.
- Internet per scaricare Maven e le dipendenze al primo build. Nessuna API cloud è richiesta durante le analisi.
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools) per ADB. Su Windows può servire il driver USB del produttore.
- [Wireshark / TShark](https://www.wireshark.org/download.html) soltanto per importare catture. Nessuna cattura live in questa versione.

ADB e TShark non vengono installati automaticamente. In **Impostazioni e dati** inserisci il percorso completo dell'eseguibile, senza virgolette o argomenti; sono supportati percorsi con spazi. Le impostazioni valgono per la sessione. Per i valori iniziali usa le variabili d'ambiente `RADARLUME_ADB` e `RADARLUME_TSHARK` oppure rendi i comandi disponibili nel `PATH`.

## Build, test e avvio

Da PowerShell, nella radice del repository:

```powershell
.\mvnw.cmd clean install
.\mvnw.cmd -pl radarlume-desktop javafx:run
```

Da Linux/macOS con sessione grafica:

```sh
sh mvnw clean install
sh mvnw -pl radarlume-desktop javafx:run
```

`install` compila, esegue unit test e integration test e rende disponibili i moduli nel repository Maven locale. `verify` esegue gli stessi controlli senza installare i moduli. Esegui prima `install` per lanciare il solo modulo desktop. I JAR non sono installer autonomi: usa il comando JavaFX indicato.

Test grafico facoltativo (richiede desktop attivo; non legge dispositivi né catture):

```powershell
.\mvnw.cmd '-Dradarlume.uiTests=true' verify
```

Genera immagini delle schermate in `radarlume-desktop/target/ui-smoke/`. È escluso per impostazione predefinita per consentire build senza display. Il sistema di riferimento iniziale è Windows 11; Linux/macOS richiedono una verifica dedicata prima di dichiararne il supporto.

## Prima lettura Android

1. Usa un dispositivo tuo o per il quale hai un'autorizzazione informata.
2. Abilita debug USB, collega un cavo dati e sblocca il telefono.
3. Accetta sul telefono la richiesta di autorizzazione di questo computer.
4. Premi **Cerca dispositivi**, seleziona quello corretto e conferma l'autorizzazione nella UI.
5. Premi **Leggi inventario**. Solo **Salva inventario locale** scrive la fotografia nel database.

Comandi utilizzati:

```text
adb devices -l
adb -s SERIAL shell pm list packages
adb -s SERIAL shell pm list packages -s
```

Nessun root, installazione, disinstallazione, modifica delle impostazioni Android o copia di dati privati. ADB può avviare il proprio server locale. La discovery mostra anche emulatori e dispositivi ADB già connessi via rete: non verifica il tipo di cavo. La visibilità dei pacchetti dipende da Android, profili e policy OEM; non rappresenta necessariamente tutti i profili del telefono. Le due letture non sono uno snapshot atomico del sistema Android.

## Analisi rete: limiti

TShark usa `-n -r`, senza risoluzione di nomi né cattura live. Sono considerati solo pacchetti TCP/UDP con indirizzi IP decodificabili. La chiave di aggregazione comprende sorgente, destinazione, protocollo e porte; le direzioni restano separate e l'intervallo è l'intera cattura. I byte rappresentano le lunghezze dei frame, non il payload. Per pacchetti incapsulati si usa la prima occorrenza dei campi: l'MVP non ricostruisce i tunnel.

- Limite file: 100 MiB; limite stdout/stderr: 16 MiB per stream; 50.000 flussi; timeout 90 secondi.
- I limiti causano un errore, non risultati troncati presentati come completi.
- Nessuna decifratura TLS, estrazione dei contenuti o attribuzione di connessioni alle app.
- Un telefono collegato via USB non espone automaticamente il proprio traffico.
- DNS, IOC, scoring, baseline, cattura live ed esportazione dei report sono ancora da implementare.

## Architettura

Monolite Maven multi-modulo, senza server e senza Spring. I moduli Maven non sono moduli JPMS; il runtime usa il classpath. Assemblaggio manuale nel desktop.

| Modulo | Package | Responsabilità |
| --- | --- | --- |
| `radarlume-domain` | `io.radarlume.domain` | Record immutabili e porte, senza dipendenze runtime esterne |
| `radarlume-application` | `io.radarlume.application` | Consenso, stato del dispositivo, orchestrazione |
| `radarlume-process` | `io.radarlume.process` | ProcessBuilder, timeout, annullamento e output limitato |
| `radarlume-adapter-adb` | `io.radarlume.adb` | Comandi ADB e parser separati |
| `radarlume-adapter-network` | `io.radarlume.network` | TShark e aggregazione |
| `radarlume-adapter-storage` | `io.radarlume.storage` | JDBC SQLite, schema v1, transazioni |
| `radarlume-desktop` | `io.radarlume.desktop` | JavaFX/CSS, composizione e task asincroni |
| `radarlume-integration-tests` | `io.radarlume` | ADB simulato → application → SQLite reale |

Application dipende solo da domain. Gli adattatori implementano le porte del dominio; ADB e rete condividono process. La UI è costruita in Java per contenere la complessità iniziale; FXML potrà essere introdotto quando le schermate cresceranno.

## Privacy e gestione errori

- Nessuna telemetria, upload o sincronizzazione. Risultati in memoria salvo salvataggio esplicito.
- Database predefinito: `${user.home}/.radarlume/inventories.db`. Contiene in chiaro seriale, modello, timestamp e nomi dei pacchetti. Non offre cifratura integrata: proteggi account e disco.
- Override directory tramite proprietà JVM `radarlume.dataDir`. Aprire la UI non crea lo storico.
- Eliminazione con `secure_delete` e `VACUUM`: non equivale a cancellazione forense su SSD e non rimuove backup esterni.
- SQL parametrizzato, salvataggio atomico e rifiuto di versioni future dello schema.
- Nessuna shell sul PC: argomenti separati, seriale validato, comandi remoti ADB fissi.
- Stdout/stderr drenati contemporaneamente; 4 MiB per stream ADB, timeout discovery 20 s e inventario 30 s per comando.
- Nessun log automatico di seriali, app o catture. Gli errori mostrano il codice di uscita senza riversare stderr nella UI.
- Annullare una scrittura già completata non la annulla retroattivamente: verifica lo storico se interrompi il salvataggio.
- `.gitignore` esclude database, catture, log, build e impostazioni IDE. Non inserire dati reali nei fixture.

## Verifica e roadmap

I test coprono stati ADB, consenso mancante, autorizzazione, parsing malformato, selezione seriale, timeout, interruzione, output eccessivo, aggregazione IPv4/IPv6, transazioni SQLite, rollback e cancellazione. Le risposte ADB sono simulate: resta necessaria una prova manuale con telefoni autorizzati di versioni diverse. Il test grafico non accede a dispositivi reali.

Prossimi incrementi:

1. Validazione su dispositivi fisici; versioni app, installatore e permessi con parser dedicati e campi mancanti espliciti.
2. Evidenze e regole spiegabili con fonte, versione e confidenza, senza equiparare un singolo permesso a malware.
3. DNS/IOC offline, conservazione configurabile e report JSON/HTML.
4. Cattura live autorizzata e correlazione solo con prove di attribuzione.
5. Packaging `jpackage`, aggiornamento dipendenze, firma installer e validazione multipiattaforma.

La licenza di distribuzione deve ancora essere scelta dal proprietario prima della pubblicazione del prodotto.

## Riferimenti

- [ADB ufficiale](https://developer.android.com/tools/adb)
- [JavaFX con Maven](https://openjfx.io/openjfx-docs/)
- [Manuale TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [SQLite JDBC](https://github.com/xerial/sqlite-jdbc)
