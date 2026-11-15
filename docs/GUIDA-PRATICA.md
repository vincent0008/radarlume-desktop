# RadarLume: primi passi nell'analisi di sicurezza mobile

Questa guida distingue ciò che osserviamo da ciò che possiamo concludere. È un percorso di laboratorio per uno sviluppatore Java; non una qualificazione professionale né una procedura forense certificata.

## 1. Tre problemi diversi

Un'app malevola sul dispositivo, un account cloud compromesso e un'intercettazione delle comunicazioni richiedono controlli diversi. Un telefono può avere app normali mentre qualcuno accede al suo account da un altro computer. L'inventario Android non vede questi accessi. Analogamente, non dimostra l'assenza di intercettazioni a livello di operatore o di spyware sofisticato.

## 2. Come funziona RadarLume

ADB permette al PC autorizzato di interrogare Android. Il programma trasforma le risposte in dati strutturati. Il motore applica regole ripetibili e mostra osservazioni, fonte e data. SQLite conserva gli inventari salvati e le impostazioni. TShark legge una cattura di rete separata: collegare il telefono via USB non cattura automaticamente Internet.

La nuova funzione **Controlli Android** legge quattro elementi: versione Android, SDK, patch dichiarata e servizi di accessibilità configurati. Una patch più vecchia di 180 giorni genera un avviso di manutenzione: la soglia è una scelta iniziale del progetto, non uno standard di compromissione. L'accessibilità genera una richiesta di verifica: lettori dello schermo e strumenti legittimi possono utilizzarla. Un dato non disponibile viene dichiarato tale.

Queste valutazioni restano in memoria e non sono ancora salvate nello storico. Il salvataggio dell'inventario conserva solo pacchetti e classificazione sistema/utente. La confidenza riguarda l'interpretazione dell'evidenza, non una probabilità matematica di infezione.

## 3. Che cosa cercare

| Osservazione | Domanda da approfondire | Cosa non dimostra da sola |
| --- | --- | --- |
| App sconosciuta al proprietario | Qual è la provenienza? Quando è stata installata? Chi firma l'APK? | Un nome insolito non implica malware |
| Accessibilità, amministrazione o accesso alle notifiche | Sono coerenti con la funzione dell'app e con il consenso del proprietario? | Un privilegio non prova che sia stato abusato |
| Microfono, posizione, SMS | Il permesso è richiesto o davvero concesso? Per quale profilo? | Un permesso concesso non prova l'utilizzo |
| Connessioni periodiche | È sincronizzazione, pubblicità o comando remoto? Quale app le genera? | Periodicità e IP estero non bastano |
| Molti byte in uscita | Backup foto? Videochiamata? Quale intervallo e quale processo? | Il volume non prova un furto di dati |
| Indicatore IOC corrispondente | La fonte è affidabile e recente? È un IP condiviso? | Un match può essere un falso positivo |

Un **IOC** è un indicatore noto, per esempio hash di un file o dominio associato a una campagna. Gli hash identificano contenuti specifici; IP e domini possono cambiare proprietario o ospitare servizi diversi. Conservare sempre fonte, data e contesto.

## 4. Rete: vedere il punto giusto

IP identifica un indirizzo, porta un servizio, DNS traduce nomi in indirizzi. TCP e UDP trasportano comunicazioni; TLS protegge il contenuto di molte sessioni. Una cattura può mostrare destinazioni, tempi e dimensioni senza rivelare ciò che è stato inviato. DNS cifrato può nascondere anche le richieste DNS.

Per attribuire traffico al telefono serve un punto di osservazione appropriato, per esempio un gateway di laboratorio attraversato dal suo traffico. Annotare assegnazioni IP, orari e configurazione: NAT e indirizzi condivisi possono confondere l'attribuzione. Per attribuirlo a una specifica app servono ulteriori evidenze; il nostro importatore PCAP non lo fa.

### Cattura con PCAPdroid e importazione in RadarLume

PCAPdroid è un'app di terzi che crea una VPN locale sul telefono: il traffico delle app passa da lì e viene scritto in un file, senza root. Vede indirizzi, porte, orari e dimensioni; non rende leggibile HTTPS.

1. In PCAPdroid scegli la modalità di salvataggio **PCAP file** e, nelle impostazioni, attiva **PCAPdroid extensions**: ogni pacchetto porta con sé UID e nome dell'app che lo ha generato. Lascia il formato PCAP: il PCAPNG di PCAPdroid non è ancora letto da RadarLume per la parte app.
2. Annota versione di PCAPdroid, versione Android, eventuale filtro per app e se IPv6 è attivo (è disattivato per impostazione predefinita: in tal caso il traffico IPv6 non viene né instradato né catturato).
3. Avvia la cattura, usa per uno o due minuti un'app nota, ferma la cattura. Android consente una sola VPN alla volta: con un'altra VPN attiva la cattura non parte o la sostituisce.
4. Porta il file sul PC e importalo dalla scheda **Rete / PCAP**. Confronta l'impronta SHA-256 mostrata con quella del file originale se vuoi dimostrare che è lo stesso.
5. Leggi prima il riquadro con intervallo, avvisi e limiti, poi le tabelle. Verifica che flussi, nomi DNS e app corrispondano a ciò che hai fatto davvero.

Cosa non concludere: una destinazione sconosciuta, molto traffico o un nome insolito non provano un'infezione. Con DNS privato (DoT) attivo su Android la tabella DNS può restare vuota. Gli indirizzi sorgente sono quelli interni della VPN di PCAPdroid, non quelli reali della rete.

## 5. Primo esercizio ripetibile

1. Usa un telefono di laboratorio tuo, annotando modello, versione e autorizzazioni concesse. Evita dati personali reali.
2. Salva l'inventario iniziale. Esegui Controlli Android e annota anche i dati mancanti.
3. Installa consapevolmente un'app di prova lecita. Ripeti l'inventario e individua il nuovo pacchetto tramite SQL. Il confronto automatico è ancora da implementare.
4. In una cattura autorizzata, osserva separatamente cinque minuti di inattività e un'azione nota, per esempio aprire una pagina. Annota inizio e fine.
5. Formula un'ipotesi e un'alternativa innocua. Cerca un secondo riscontro indipendente prima di concludere.
6. Scrivi: dati raccolti, metodo, limiti, risultato e verifiche successive. Non usare “sicuro al 100%”.

Non serve installare malware reale per imparare. Fixture sintetici, emulatori e applicazioni didattiche permettono test ripetibili. Anche il debug USB modifica la configurazione del dispositivo: l'MVP è diagnostico, non una copia forense immutabile.

## 6. Lavorare con affidabilità

Concorda scopo e consenso, minimizza i dati, registra versioni degli strumenti e passaggi effettuati. Per file acquisiti conserva originali, hash SHA-256 e copie di lavoro; l'hash rileva modifiche successive ma non certifica la veridicità della sorgente. Proteggi report e backup e definisci tempi di cancellazione.

Se c'è un possibile reato, un caso di stalking o una contestazione legale, evita improvvisazioni e coinvolgi un professionista qualificato: reset, disinstallazioni e modifiche possono cancellare elementi utili. La reputazione professionale cresce con risultati riproducibili, revisione indipendente, misura dei falsi positivi e comunicazione onesta dei limiti.

## 7. Percorso di studio

- Prima: reti TCP/IP, DNS, TLS, Linux e strumenti Wireshark; spiega una cattura normale prima di cercare anomalie.
- Poi: Android, sandbox, UID, firma APK, permessi, componenti e profili utente.
- Quindi: laboratorio di analisi statica/dinamica di app didattiche, mantenendo separati sicurezza dell'app e compromissione del telefono.
- Infine: metodologia forense, raccolta e conservazione delle evidenze, report e validazione con colleghi esperti.

Per un futuro antivirus serviranno dataset rappresentativi e autorizzati, misure di precisione e richiamo, aggiornamenti sicuri, gestione dei falsi positivi e valutazione dei limiti delle API Android. Un'app Android avrà capacità diverse dal desktop con ADB.

## Fonti per proseguire

- [Android ADB](https://developer.android.com/tools/adb): comunicazione e autorizzazione del dispositivo.
- [Bollettini Android](https://source.android.com/docs/security/bulletin): patch e problemi corretti; non una diagnosi del singolo telefono.
- [OWASP MASTG](https://mas.owasp.org/MASTG/): metodologia e laboratorio per testare la sicurezza delle app mobili.
- [Mobile Verification Toolkit](https://docs.mvt.re/en/latest/): analisi consensuale di tracce di compromissione e interpretazione dei risultati.
- [Manuale TShark](https://www.wireshark.org/docs/man-pages/tshark.html): lettura e acquisizione delle catture.
