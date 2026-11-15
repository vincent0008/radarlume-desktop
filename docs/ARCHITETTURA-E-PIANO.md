# Architettura e stato del piano

## Decisione

Conservare Java 21, JavaFX, monolite Maven e SQLite locale. È una base proporzionata al desktop offline; non esiste un'architettura ottimale senza requisiti e misure. Microservizi e PostgreSQL non risolvono gli attuali problemi di acquisizione e qualità delle evidenze. PostgreSQL potrà servire a un backend condiviso, dietro API, se nascerà una versione multiutente.

Le porte isolano il dominio da ADB, TShark e JDBC. Sono ora presenti anche SettingsRepository e SecurityEvidenceCollector; AndroidAssessmentService verifica consenso e stato, poi valuta evidenze senza dipendere da JavaFX. Le regole hanno identificativo e versione, gravità, confidenza e riferimento all'evidenza.

## Modifiche da fare prima di ampliare molto le funzioni

1. Estrarre le viste JavaFX e il coordinamento dei task da RadarLumeApplication: non aggiungere tutta la futura dashboard alla stessa classe.
2. Centralizzare migrazioni e connessioni SQLite quando introdurremo lo storico delle evidenze. In questo incremento lo schema passa a v2 con una tabella impostazioni; gli inventari v1 sono conservati.
3. Introdurre una sessione di acquisizione persistita, con stato completo/parziale/annullato, profilo Android, versione collector e timestamp per evidenza. I controlli attuali sono ancora solo in memoria.
4. Estrarre ogni regola in una classe indipendente quando supereremo le due regole Android iniziali; soglie configurabili e test di regressione su fixture anonimizzati.
5. Tenere separati raccolta, interpretazione, reputazione e report. Nessun upload implicito a servizi esterni.

## Stato dei 24 punti

“Parziale” significa che esiste una prima implementazione, ma manca una parte necessaria del requisito.

| # | Punto | Stato |
|---|---|---|
|1|Repository Maven multi-modulo|Implementato|
|2|Modelli domain e porte|Implementato, da estendere con la sessione persistita|
|3|JavaFX e navigazione|Implementato|
|4|SQLite e test base|Implementato; impostazioni persistenti v2|
|5|Discovery e autorizzazione|Implementato; prima prova reale riuscita dell'utente|
|6|Inventario e proprietà sistema|Parziale: nomi/tipo, versione Android/SDK/patch; mancano dettagli app|
|7|Parser e metadati|Parziale: parser base, senza versioni/installatore/permessi app|
|8|Errori e versioni Android|Parziale: errori e dati mancanti; manca matrice OEM/versioni|
|9|Regole Android iniziali|Implementate due regole euristiche, da validare sul campo|
|10|Evidence e Finding|Implementati; persistenza da fare|
|11|Severity e confidence|Implementati, senza punteggio probabilistico|
|12|Test e dati simulati|Parziale: test sintetici; manca dataset rappresentativo|
|13|Import PCAP/PCAPNG|Implementato; verificato con TShark reale su catture sintetiche nei formati PCAPdroid (IP grezzo, estensioni, file troncato). Cattura reale da telefono ancora da validare|
|14|Flussi e DNS|Flussi direzionali con orari, SNI e app da metadati PCAPdroid; nomi DNS in chiaro; host delle richieste HTTP non cifrate. Prime regole di rete NET-001/002/003 in `NetworkAssessmentService`, con soglie euristiche da tarare. Risultati solo in memoria|
|15|IOC con feed di test|Da fare|
|16|Cattura live autorizzata|Da fare|
|17|Associazione dispositivo/rete|Da fare|
|18|Report HTML/JSON|Da fare|
|19|Storico e confronto|Parziale: inventari e ultimo salvataggio; confronto da fare|
|20|Dashboard completa|Da fare|
|21|Dispositivi/versioni differenti|Da fare|
|22|Timeout e interruzioni|Implementati e testati; da estendere ai nuovi collector|
|23|Packaging Windows|Da fare|
|24|Documentazione, privacy, test finali|Parziale: README e guida; validazione finale da fare|

Prossimo incremento consigliato: dettagli del singolo pacchetto (versione, installatore, permessi richiesti/concessi), fixture per più versioni Android e persistenza delle evidenze. Poi DNS/IOC offline e report. La cattura live seguirà quando possiamo validare anche provenienza e limiti dei dati.
