# RadarLume Desktop

Primo MVP diagnostico desktop, Java 21 e JavaFX. Raccoglie un inventario Android tramite ADB autorizzato e importa metadati di rete da catture PCAP/PCAPNG con TShark. Il nome provvisorio del progetto era Sentinel Desktop.

**Questo MVP non è un antivirus e non certifica l'assenza di malware o intercettazioni.** Include due controlli Android contestuali (patch datate e accessibilità configurata). Non contiene ancora regole IOC, analisi APK o correlazione app/connessioni. Un errore di raccolta non viene trasformato in un risultato rassicurante.

## Nuovo incremento: impostazioni ed evidenze

In **Impostazioni e dati**, modifica ADB/TShark e premi **Salva percorsi**. I valori vengono conservati nella tabella `tool_settings` e caricati al riavvio. Precedenza: valori salvati, variabili d'ambiente, nomi predefiniti. Il salvataggio verifica il formato, non l'esistenza o l'identità degli eseguibili. La cancellazione degli inventari conserva le impostazioni. La migrazione v1 → v2 conserva gli inventari esistenti; non riaprire il database migrato con la vecchia versione dell'app.

In **Android**, seleziona il dispositivo, conferma l'autorizzazione e premi **Controlli Android**. Si raccolgono versione, SDK, patch e servizi di accessibilità configurati. La finestra mostra fonti, timestamp, regole versionate, gravità e confidenza; i dati mancanti sono espliciti. Questi controlli restano in memoria: **Salva inventario locale** non salva le evidenze. Non includono ancora metadati e permessi delle singole app.

- [Guida pratica per iniziare](docs/GUIDA-PRATICA.md)
- [Architettura e stato dei 24 punti](docs/ARCHITETTURA-E-PIANO.md)

## Funzionalità

- Discovery ADB con stati autorizzato, non autorizzato, offline e permessi mancanti.
- Selezione esplicita e consenso prima dell'inventario; nuova verifica dello stato al momento della lettura.
- Nomi dei pacchetti e classificazione sistema/utente, con filtro nella UI; per ogni app anche **versione**, **origine di installazione** e **permessi** letti da `dumpsys package` (best-effort, non persistiti nello storico).
- Controlli Android sui metadati app, nella finestra **Controlli Android**. Osservazioni, non verdetti:
  - `AND-003`: app non di sistema installata da un'origine diversa dagli store conosciuti (origine non registrata o sideload). Confidenza bassa: il sideload è legittimo (F-Droid, APK diretti).
  - `AND-004`: app non di sistema con almeno due categorie di permessi sensibili concessi (SMS, posizione, microfono, fotocamera, accessibilità…). Riporta nomi e categorie, mai l'uso; avere un permesso non dimostra come viene usato.
  - `DATA-008`: metadati app non letti (versione/origine/permessi assenti): AND-003 e AND-004 non vengono eseguite.
- Salvataggio volontario SQLite, caricamento dell'ultimo inventario e cancellazione dello storico con conferma.
- Importazione PCAP/PCAPNG (anche esportati da PCAPdroid): flussi TCP/UDP IPv4/IPv6 aggregati per direzione, pacchetti, byte IP, primo/ultimo orario, nome TLS (SNI) in chiaro, nomi DNS in chiaro con indirizzi restituiti, impronta SHA-256 del file.
- App associata al flusso solo se dichiarata dalla cattura stessa (estensioni PCAPdroid in formato PCAP); mai dedotta da IP o orari.
- Prime regole di rete, mostrate nella scheda **Osservazioni** dopo ogni importazione. Indicano dove guardare meglio, non sono verdetti:
  - `NET-001`: richiesta HTTP non cifrata effettivamente decodificata (non la sola porta 80). Confidenza alta: è un fatto osservato.
  - `NET-002`: verso uno stesso indirizzo, almeno 512 KiB inviati e almeno il doppio del ricevuto. Confidenza bassa: backup, foto e chiamate producono lo stesso schema, e la direzione è stimata da porte e ordine dei pacchetti.
  - `NET-003`: un'app contatta almeno 20 indirizzi remoti distinti. Informativa; richiede i metadati app.
  - `DATA-003`…`DATA-006`: cattura troncata, metadati app assenti, nessun pacchetto analizzabile, elenco limitato. Servono a non far passare un'analisi incompleta per un risultato pulito.
  - `NET-004`: richieste leggibili in cui l'indirizzo, il corpo, il Referer o un'intestazione `Authorization` contengono dati che per nome (`lat`, `adid`, `email`, `password`…) o forma (un indirizzo email) suggeriscono informazioni personali. Riporta nomi e conteggi, mai i valori. Confidenza bassa: il nome di un parametro non dimostra il contenuto.
  - `DATA-007`: quante connessioni TLS sono diventate leggibili con le chiavi fornite e quante no. Delle richieste leggibili sono esaminati indirizzo, intestazioni e corpo lato richiesta; non le risposte.
  - Le soglie sono euristiche del progetto, da tarare con catture reali. Il contenuto rimasto cifrato non è esaminato.
- Decrittazione TLS con chiavi fornite dall'utente: se accanto alla cattura c'è un file con lo stesso nome ed estensione `.keylog` (formato SSLKEYLOGFILE, scritto da PCAPdroid quando la sua decrittazione TLS è attiva), RadarLume lo passa a TShark e mostra le richieste HTTP/1 e HTTP/2 nella scheda **Richieste HTTP**, con metodo, host, percorso, intestazioni presenti, Referer, Content-Type e il **corpo delle richieste** (POST compresi). RadarLume non intercetta né forza nulla: legge solo ciò che le chiavi consentono. Disattivabile con la casella accanto al pulsante di importazione.
- Operazioni fuori dal thread JavaFX, annullamento, timeout e limiti di output.

## Prerequisiti

- JDK **21**, con `JAVA_HOME` configurato. Maven Wrapper scarica Maven 3.9.11 al primo avvio.
- Internet per scaricare Maven e le dipendenze al primo build. Nessuna API cloud è richiesta durante le analisi.
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools) per ADB. Su Windows può servire il driver USB del produttore.
- [Wireshark / TShark](https://www.wireshark.org/download.html) soltanto per importare catture. Nessuna cattura live in questa versione.

ADB e TShark non vengono installati automaticamente. In **Impostazioni e dati** inserisci il percorso completo dell'eseguibile, senza virgolette o argomenti; sono supportati percorsi con spazi. Premi **Salva percorsi** per conservarli. In assenza di impostazioni salvate puoi usare `RADARLUME_ADB` e `RADARLUME_TSHARK` oppure rendere i comandi disponibili nel `PATH`.

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

TShark usa `-n -r`, senza risoluzione di nomi né cattura live. Sono considerati solo pacchetti TCP/UDP con indirizzi IP decodificabili; i messaggi ICMP sono esclusi perché citano intestazioni altrui. La chiave di aggregazione comprende sorgente, destinazione, protocollo e porte; le direzioni restano separate e l'intervallo è l'intera cattura. I byte sono la lunghezza del pacchetto IP (lunghezza del frame solo se quella IP manca), così il trailer PCAPdroid non gonfia i totali. Per pacchetti incapsulati si usa la prima occorrenza dei campi: l'MVP non ricostruisce i tunnel.

Nomi DNS e SNI sono letti solo se in chiaro: DNS cifrato (DoH/DoT), ECH e QUIC non decodificato li nascondono, quindi una tabella vuota non indica assenza di traffico. Gli orari sono quelli scritti dal dispositivo di cattura. I nomi provenienti dalla cattura sono trattati come dati non fidati e sostituiti da un segnaposto se non hanno forma di nome host.

Metadati app: sono letti dal trailer che PCAPdroid aggiunge con l'opzione *PCAPdroid extensions* nel formato PCAP (UID e nome visualizzato dell'app troncato a 19 byte; verificato su una cattura reale: la documentazione di PCAPdroid parla di nome del pacchetto, ma il file contiene ad esempio "Facebook"). Il formato PCAPNG di PCAPdroid usa blocchi personalizzati che RadarLume non legge ancora: in quel caso nessuna attribuzione.

- Limite file: 100 MiB; limite output TShark: 64 MiB (una riga per pacchetto, circa mezzo milione di pacchetti); 50.000 flussi; 20.000 nomi DNS; timeout 90 secondi.
- I limiti causano un errore, non risultati troncati presentati come completi. Unica eccezione: un file che termina a metà pacchetto viene importato per la parte leggibile ed è marcato come **parziale**; il superamento del limite dei nomi DNS è segnalato come avviso.
- Decrittazione TLS: solo con il file `.keylog` (massimo 16 MiB, formato verificato prima dell'uso). Sono letti metodo, host, indirizzo, intestazioni presenti, Referer, Content-Type e il **corpo lato richiesta** (massimo 20.000 richieste, indirizzo 2.000 caratteri, corpo 64 KiB per richiesta, 8 MiB complessivi; il corpo binario è indicato ma non mostrato). I corpi e le intestazioni delle **risposte** non sono estratti, e dei valori di cookie/Authorization si registra solo la presenza, non il contenuto. Il corpo lato richiesta è letto da TShark come esadecimale (robusto rispetto a spazi e byte arbitrari) e correlato per flusso TCP e `stream id` HTTP/2. QUIC/HTTP3 non è decifrato. Le app che non accettano il certificato di PCAPdroid (la maggior parte, da Android 7, senza root) restano cifrate. Verificato su una sola cattura reale di Chrome (938 connessioni TLS leggibili su 1.172, 481 richieste con corpo); nessun test automatico esegue una decrittazione vera, i test coprono il passaggio delle chiavi, la correlazione corpo/richiesta e la lettura dell'output.
- Il file `.keylog` e le richieste decifrate contengono dati personali (indirizzi visitati, identificativi): restano in memoria, non vengono salvati nel database e `*.keylog` è escluso dal repository.
- Nessuna attribuzione alle app oltre ai metadati dichiarati dalla cattura.
- Un telefono collegato via USB non espone automaticamente il proprio traffico.
- IOC, scoring, baseline, cattura live, salvataggio delle analisi di rete ed esportazione dei report sono ancora da implementare.

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
