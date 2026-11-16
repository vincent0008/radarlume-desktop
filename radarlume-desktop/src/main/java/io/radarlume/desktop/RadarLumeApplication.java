package io.radarlume.desktop;

import io.radarlume.adb.AdbDeviceInspector;
import io.radarlume.adb.AdbSecurityEvidenceCollector;
import io.radarlume.application.AndroidAssessmentService;
import io.radarlume.application.AppInventoryAssessmentService;
import io.radarlume.application.DeviceScanService;
import io.radarlume.application.NetworkAssessmentService;
import io.radarlume.domain.*;
import io.radarlume.network.TsharkTrafficAnalyzer;
import io.radarlume.process.BoundedProcessRunner;
import io.radarlume.storage.SqliteInventoryRepository;
import javafx.application.Application;
import javafx.beans.property.*;
import javafx.collections.*;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.*;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.function.*;

public final class RadarLumeApplication extends Application {
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> { Thread t = new Thread(r, "radarlume-worker"); t.setDaemon(true); return t; });
    private final BooleanProperty busy = new SimpleBooleanProperty();
    private final Label status = new Label("Pronto. Collega un dispositivo Android e abilita il debug USB.");
    private final TextField adbPath = new TextField(System.getenv().getOrDefault("RADARLUME_ADB", "adb"));
    private final TextField tsharkPath = new TextField(System.getenv().getOrDefault("RADARLUME_TSHARK", "tshark"));
    private final ComboBox<Device> devices = new ComboBox<>();
    private final CheckBox consent = new CheckBox("Sono autorizzato ad analizzare il dispositivo selezionato");
    private final ObservableList<InstalledApp> apps = FXCollections.observableArrayList();
    /** One output line per packet: 64 MiB is roughly half a million packets. Larger captures are refused, not cut. */
    private static final int TSHARK_OUTPUT_LIMIT = 64 * 1024 * 1024;
    private static final java.time.format.DateTimeFormatter TIME = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(java.time.ZoneOffset.UTC);
    private final ObservableList<NetworkFlow> flows = FXCollections.observableArrayList();
    private final ObservableList<DnsName> dnsNames = FXCollections.observableArrayList();
    private final ObservableList<HttpRequest> requests = FXCollections.observableArrayList();
    private final CheckBox useKeylog = new CheckBox("Usa le chiavi TLS (.keylog) se presenti accanto alla cattura");
    private static final String NO_FINDINGS_YET = "Le osservazioni appariranno qui dopo l'importazione di una cattura.";
    private final TextArea networkFindings = new TextArea(NO_FINDINGS_YET);
    private final TabPane results = new TabPane();
    private final BooleanProperty savable = new SimpleBooleanProperty();
    private final Label inventoryLabel = new Label("Nessun inventario acquisito");
    private final Label networkLabel = new Label("Nessuna cattura importata");
    private Inventory inventory;
    private Task<?> active;
    private InventoryRepository repository;
    private SettingsRepository settingsRepository;

    @Override public void start(Stage stage) {
        Path db = Path.of(System.getProperty("radarlume.dataDir", Path.of(System.getProperty("user.home"), ".radarlume").toString()), "inventories.db");
        repository = new SqliteInventoryRepository(db);
        settingsRepository = (SettingsRepository) repository;
        Label title = new Label("RadarLume"); title.getStyleClass().add("title");
        Label subtitle = new Label("Dispositivi Android · Inventario app · Analisi PCAP offline");
        Label scope = new Label("MVP diagnostico: i risultati non attestano l'assenza di malware. Nessun dato viene inviato a servizi cloud.");
        scope.setWrapText(true); scope.setMinHeight(Region.USE_PREF_SIZE);
        VBox header = new VBox(6, title, subtitle, scope); header.setPadding(new Insets(22));
        ScrollPane settings = new ScrollPane(settingsPane(db)); settings.setFitToWidth(true);
        TabPane tabs = new TabPane(tab("Android", androidPane()), tab("Rete / PCAP", networkPane(stage)), tab("Impostazioni e dati", settings));
        Button cancel = new Button("Annulla"); cancel.disableProperty().bind(busy.not());
        cancel.setOnAction(e -> { if (active != null) active.cancel(true); });
        ProgressIndicator progress = new ProgressIndicator(); progress.setPrefSize(22,22); progress.visibleProperty().bind(busy);
        status.setWrapText(true); status.setMaxWidth(Double.MAX_VALUE); HBox.setHgrow(status, Priority.ALWAYS);
        HBox footer = new HBox(12, progress, status, cancel); footer.setPadding(new Insets(14));
        BorderPane root = new BorderPane(tabs, header, null, footer, null);
        Scene scene = new Scene(root, 1080, 740);
        scene.getStylesheets().add(getClass().getResource("/radarlume.css").toExternalForm());
        stage.setTitle("RadarLume Desktop · MVP 0.1"); stage.setMinWidth(820); stage.setMinHeight(580); stage.setScene(scene); stage.show();
        run("Caricamento impostazioni…", settingsRepository::loadSettings, saved -> {
            saved.ifPresent(value -> { adbPath.setText(value.adb()); tsharkPath.setText(value.tshark()); });
            status.setText(saved.isPresent() ? "Percorsi salvati caricati. Pronto." : "Pronto. Configura e salva i percorsi degli strumenti.");
        });
    }
    private Tab tab(String title, javafx.scene.Node content) { Tab tab = new Tab(title, content); tab.setClosable(false); return tab; }
    private DeviceScanService service() {
        return new DeviceScanService(new AdbDeviceInspector(tool(adbPath), new BoundedProcessRunner(4 * 1024 * 1024)), Clock.systemUTC());
    }
    private static String tool(TextField field) { return field.getText().strip(); }
    private Button button(String name, Runnable action) {
        Button b = new Button(name); b.disableProperty().bind(busy); b.setOnAction(e -> action.run()); return b;
    }
    private VBox androidPane() {
        Button discover = button("Cerca dispositivi", () -> {
            DeviceScanService svc = service();
            devices.getItems().clear(); clearInventory();
            run("Ricerca dispositivi…", svc::discover, list -> {
                devices.getItems().setAll(list);
                if (!list.isEmpty()) devices.getSelectionModel().selectFirst();
                status.setText(list.isEmpty() ? "Nessun dispositivo ADB. Verifica cavo, driver e debug USB." : list.size() + " dispositivi. Autorizza il PC sul telefono se richiesto.");
            });
        });
        devices.setPrefWidth(500); devices.disableProperty().bind(busy);
        devices.valueProperty().addListener((o, old, selected) -> { consent.setSelected(false); clearInventory(); });
        consent.disableProperty().bind(busy);
        Button scan = new Button("Leggi inventario");
        scan.disableProperty().bind(busy.or(consent.selectedProperty().not()).or(devices.valueProperty().isNull()));
        scan.setOnAction(e -> {
            Device selected = devices.getValue(); boolean allowed = consent.isSelected(); DeviceScanService svc = service(); clearInventory();
            run("Lettura pacchetti…", () -> svc.scan(selected.serial(), allowed), value -> {
                showInventory(value, false); savable.set(true); status.setText("Inventario completato: " + value.apps().size() + " pacchetti. Dati in memoria; salvataggio facoltativo.");
            });
        });
        Button save = new Button("Salva inventario locale"); save.disableProperty().bind(busy.or(savable.not()));
        save.setOnAction(e -> { Inventory snapshot = inventory; run("Salvataggio…", () -> { repository.save(snapshot); return true; }, ok -> { savable.set(false); status.setText("Inventario salvato sul PC."); }); });
        TextField filter = new TextField(); filter.setPromptText("Filtra per nome pacchetto");
        FilteredList<InstalledApp> filtered = new FilteredList<>(apps);
        filter.textProperty().addListener((o, a, value) -> filtered.setPredicate(app -> app.packageName().toLowerCase(java.util.Locale.ROOT).contains(value.toLowerCase(java.util.Locale.ROOT))));
        TableView<InstalledApp> table = new TableView<>(filtered);
        table.getColumns().add(column("Pacchetto", InstalledApp::packageName, 430));
        table.getColumns().add(column("Tipo", a -> a.system() ? "Sistema" : "Utente", 90));
        table.getColumns().add(column("Versione", a -> a.metadata().versionName().isEmpty() ? "—" : a.metadata().versionName(), 130));
        table.getColumns().add(column("Origine", RadarLumeApplication::origin, 230));
        table.setPlaceholder(new Label("L'inventario apparirà qui dopo una lettura autorizzata."));
        Label note = new Label("Pacchetti, tipo, versione e origine di installazione (letti da dumpsys package, best-effort). I permessi e l'origine sono valutati dai controlli Android; un'origine o un permesso non sono di per sé un verdetto malware."); note.setWrapText(true);
        Button assess = new Button("Controlli Android");
        assess.disableProperty().bind(busy.or(consent.selectedProperty().not()).or(devices.valueProperty().isNull()));
        assess.setOnAction(event -> {
            String serial = devices.getValue().serial(); boolean authorized = consent.isSelected();
            String adb = tool(adbPath); var runner = new BoundedProcessRunner(1024 * 1024);
            var service = new AndroidAssessmentService(new AdbDeviceInspector(adb, runner),
                new AdbSecurityEvidenceCollector(adb, runner, Clock.systemUTC()), Clock.systemUTC());
            run("Raccolta evidenze Android…", () -> service.assess(serial, authorized), result -> {
                StringBuilder text = new StringBuilder("Dispositivo: " + result.serial() + "\nRisultati in memoria, non salvati nello storico.\n\nEVIDENZE\n");
                result.evidence().forEach(e -> text.append(e.key()).append(": ").append(e.status() == Evidence.Status.AVAILABLE ? e.value() : "NON DISPONIBILE")
                    .append("\nFonte: ").append(e.source()).append("\nData UTC: ").append(e.collectedAt()).append("\n\n"));
                text.append("VALUTAZIONI\n");
                var findings = new java.util.ArrayList<>(result.findings());
                Inventory snapshot = inventory;
                if (snapshot != null && snapshot.device().serial().equals(result.serial()))
                    findings.addAll(AppInventoryAssessmentService.evaluate(snapshot.apps(), result.serial()));
                else
                    text.append("Metadati app non valutati: leggere prima l'inventario con \"Leggi inventario\" per analizzare origine e permessi.\n\n");
                findings.forEach(f -> text.append(f.ruleId()).append(" v").append(f.ruleVersion()).append(" · ").append(f.severity())
                    .append(" · confidenza ").append(f.confidence()).append(" · evidenza ").append(f.evidenceKey())
                    .append("\n").append(f.explanation()).append("\n").append(f.nextStep()).append("\n\n"));
                text.append("Nessun verdetto di assenza di malware: questi controlli coprono patch dichiarate, servizi di accessibilità, origine delle app e permessi sensibili dichiarati.");
                TextArea area = new TextArea(text.toString()); area.setEditable(false); area.setWrapText(true); area.setPrefSize(780,500);
                Dialog<Void> dialog = new Dialog<>(); dialog.setTitle("Evidenze e controlli Android"); dialog.getDialogPane().setContent(area);
                dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE); dialog.setResizable(true); dialog.show();
                status.setText("Controlli completati: " + findings.size() + " osservazioni. Nessun verdetto malware.");
            });
        });
        VBox pane = pane(new HBox(12, discover, devices), consent, new HBox(12, scan, save, assess), inventoryLabel, filter, table, note);
        VBox.setVgrow(table, Priority.ALWAYS); return pane;
    }
    private VBox networkPane(Stage stage) {
        Label note = new Label("Importa soltanto catture che sei autorizzato ad analizzare, per esempio esportate da PCAPdroid. "
                + "Il collegamento USB non rende automaticamente visibile il traffico del telefono. "
                + "Sono aggregati i pacchetti TCP/UDP IPv4/IPv6 per direzione. L'app è mostrata solo se dichiarata dai metadati della cattura; "
                + "i contenuti cifrati vengono letti solo se accanto alla cattura c'è il file .keylog con le chiavi TLS esportate da PCAPdroid. "
                + "Le richieste decifrate possono contenere dati personali: restano in memoria e non vengono salvate.");
        note.setWrapText(true);
        networkLabel.setWrapText(true);
        Button open = button("Importa PCAP / PCAPNG", () -> {
            FileChooser chooser = new FileChooser(); chooser.setTitle("Seleziona cattura autorizzata");
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Catture di rete", "*.pcap", "*.pcapng", "*.cap"));
            var file = chooser.showOpenDialog(stage); if (file == null) return;
            var analyzer = new TsharkTrafficAnalyzer(tool(tsharkPath), new BoundedProcessRunner(TSHARK_OUTPUT_LIMIT));
            // PCAPdroid writes the TLS session keys next to the capture, with the same name and the .keylog extension.
            String name = file.getName(); int dot = name.lastIndexOf('.');
            Path sibling = file.toPath().resolveSibling((dot > 0 ? name.substring(0, dot) : name) + ".keylog");
            Path keylog = useKeylog.isSelected() && java.nio.file.Files.isRegularFile(sibling) ? sibling : null;
            flows.clear(); dnsNames.clear(); requests.clear(); networkFindings.setText(NO_FINDINGS_YET); networkLabel.setText("Nessuna analisi completata");
            run(keylog == null ? "Analisi cattura…" : "Analisi cattura con chiavi TLS…", () -> { var analysis = analyzer.analyze(file.toPath(), keylog); return Map.entry(analysis, NetworkAssessmentService.evaluate(analysis)); }, done -> {
                CaptureAnalysis result = done.getKey(); List<Finding> findings = done.getValue();
                flows.setAll(result.flows()); dnsNames.setAll(result.dnsNames()); requests.setAll(result.requests());
                networkLabel.setText(describe(result) + "\n• " + (keylog != null ? "Chiavi TLS lette da " + keylog.getFileName() + ": contenuto HTTP leggibile in " + result.tls().decrypted() + " connessioni TLS su " + result.tls().connections() + "."
                        : useKeylog.isSelected() ? "Nessun file " + sibling.getFileName() + " accanto alla cattura: il contenuto cifrato non è stato letto."
                        : "Uso delle chiavi TLS disattivato: il contenuto cifrato non è stato letto."));
                networkFindings.setText(describe(findings)); results.getSelectionModel().selectFirst();
                long toCheck = findings.stream().filter(f -> f.ruleId().startsWith("NET-")).count();
                status.setText(result.packets() == 0 ? "Nessun pacchetto TCP/UDP IP decodificabile. Non è un giudizio di sicurezza."
                        : (result.truncated() ? "Importazione PARZIALE (file troncato). " : "Importazione completata. ")
                        + toCheck + " osservazioni da approfondire. Nessun verdetto malware; dati in memoria.");
            });
        });
        TableView<NetworkFlow> table = new TableView<>(flows);
        table.getColumns().add(column("Sorgente", NetworkFlow::source, 150));
        table.getColumns().add(column("Destinazione", NetworkFlow::destination, 150));
        table.getColumns().add(column("Protocollo", NetworkFlow::protocol, 80));
        table.getColumns().add(column("Porta sorg.", NetworkFlow::sourcePort, 85));
        table.getColumns().add(column("Porta dest.", NetworkFlow::destinationPort, 85));
        table.getColumns().add(column("Nome TLS (SNI)", NetworkFlow::serverName, 190));
        table.getColumns().add(column("HTTP in chiaro (Host)", NetworkFlow::httpHost, 170));
        table.getColumns().add(column("App (metadati cattura)", f -> f.app() == null ? "" : f.app().toString(), 210));
        table.getColumns().add(column("Pacchetti", f -> Long.toString(f.packets()), 80));
        table.getColumns().add(column("Byte IP", f -> Long.toString(f.bytes()), 80));
        table.getColumns().add(column("Primo (UTC)", f -> TIME.format(f.firstSeen()), 150));
        table.getColumns().add(column("Ultimo (UTC)", f -> TIME.format(f.lastSeen()), 150));
        table.setPlaceholder(new Label("Nessuna cattura importata"));
        TableView<DnsName> dns = new TableView<>(dnsNames);
        dns.getColumns().add(column("Nome DNS richiesto", DnsName::name, 320));
        dns.getColumns().add(column("Richieste", d -> Long.toString(d.queries()), 80));
        dns.getColumns().add(column("Risposte", d -> Long.toString(d.responses()), 80));
        dns.getColumns().add(column("Indirizzi nelle risposte", d -> String.join(", ", d.addresses()), 340));
        dns.getColumns().add(column("Primo (UTC)", d -> TIME.format(d.firstSeen()), 150));
        dns.setPlaceholder(new Label("Nessun nome DNS in chiaro da mostrare. Dopo un'importazione, con DNS cifrato è normale: non significa assenza di traffico."));
        TableView<HttpRequest> http = new TableView<>(requests);
        http.getColumns().add(column("Ora (UTC)", r -> TIME.format(r.time()), 150));
        http.getColumns().add(column("App (metadati cattura)", r -> r.app() == null ? "" : r.app().toString(), 170));
        http.getColumns().add(column("Trasporto", r -> r.decrypted() ? "TLS decifrato" : "IN CHIARO", 110));
        http.getColumns().add(column("Metodo", HttpRequest::method, 70));
        http.getColumns().add(column("Host", HttpRequest::host, 230));
        http.getColumns().add(column("Percorso e parametri", HttpRequest::path, 520));
        http.getColumns().add(column("Corpo", RadarLumeApplication::bodyCell, 150));
        http.setPlaceholder(new Label("Nessuna richiesta HTTP leggibile. Senza il file .keylog di PCAPdroid si vedono solo le richieste non cifrate."));
        // Headers and body can be long and may contain personal data: shown on demand, only for the selected request.
        TextArea detail = new TextArea(); detail.setEditable(false); detail.setWrapText(true); detail.setPrefRowCount(10);
        detail.setPromptText("Seleziona una richiesta per vederne intestazioni e corpo.");
        http.getSelectionModel().selectedItemProperty().addListener((o, a, r) -> detail.setText(r == null ? "" : requestDetail(r)));
        VBox httpBox = new VBox(6, http, new Label("Dettaglio della richiesta selezionata (resta in memoria, non salvato):"), detail);
        VBox.setVgrow(http, Priority.ALWAYS);
        networkFindings.setEditable(false); networkFindings.setWrapText(true);
        results.getTabs().setAll(tab("Osservazioni", networkFindings), tab("Flussi", table), tab("Richieste HTTP", httpBox), tab("Nomi DNS in chiaro", dns));
        useKeylog.setSelected(true);
        VBox pane = pane(note, new HBox(12, open, useKeylog), networkLabel, results); VBox.setVgrow(results, Priority.ALWAYS); return pane;
    }
    private static String bodyCell(HttpRequest r) {
        if (r.bodyBinary()) return r.bodyBytes() + " byte binari";
        if (r.bodyBytes() == 0) return "";
        return r.bodyBytes() + " byte" + (r.bodyTruncated() ? " (troncato)" : "");
    }
    /** Full view of the selected request: metadata, headers present and the body text, shown only on selection. */
    private static String requestDetail(HttpRequest r) {
        StringBuilder text = new StringBuilder(r.method()).append(' ').append(r.host()).append(r.path())
                .append("\nTrasporto: ").append(r.decrypted() ? "TLS decifrato con le chiavi fornite" : "inviata in chiaro (HTTP)")
                .append("\nApp: ").append(r.app() == null ? "non indicata" : r.app().toString());
        if (!r.headerNames().isEmpty()) text.append("\nIntestazioni presenti: ").append(String.join(", ", r.headerNames()));
        if (!r.referer().isEmpty()) text.append("\nReferer: ").append(r.referer());
        if (!r.origin().isEmpty()) text.append("\nOrigin: ").append(r.origin());
        if (!r.contentType().isEmpty()) text.append("\nContent-Type: ").append(r.contentType());
        text.append("\n\nCorpo (").append(r.bodyBytes()).append(" byte").append(r.bodyTruncated() ? ", troncato" : "").append("):\n");
        text.append(r.bodyBinary() ? "(contenuto binario, non mostrato)" : r.bodyBytes() == 0 ? "(nessun corpo)" : r.body());
        return text.toString();
    }
    /** Provenance and limits of the imported capture, shown above the tables so results are never read without them. */
    private static String describe(CaptureAnalysis result) {
        StringBuilder text = new StringBuilder(result.fileName()).append(" · ").append(result.fileBytes()).append(" byte · SHA-256 ").append(result.sha256());
        text.append("\nPacchetti TCP/UDP: ").append(result.packets()).append(" · flussi direzionali: ").append(result.flows().size())
            .append(" · nomi DNS: ").append(result.dnsNames().size());
        if (result.firstPacket() != null)
            text.append("\nIntervallo (UTC, orologio del dispositivo di cattura): ").append(TIME.format(result.firstPacket())).append(" → ").append(TIME.format(result.lastPacket()));
        result.warnings().forEach(warning -> text.append("\n• ").append(warning));
        return text.toString();
    }
    /** Same layout as the Android checks: rule, version, severity, confidence, what it refers to, why, what to do next. */
    private static String describe(List<Finding> findings) {
        StringBuilder text = new StringBuilder("Le osservazioni indicano dove guardare meglio: non sono verdetti. Regole applicate: "
                + "NET-001 HTTP in chiaro · NET-002 invio molto superiore alla ricezione · NET-003 molte destinazioni per app · "
                + "NET-004 parametri che suggeriscono dati personali nelle richieste leggibili.\n\n");
        if (findings.stream().noneMatch(f -> f.ruleId().startsWith("NET-"))) text.append("Nessuna delle quattro regole è scattata. Non equivale a \"nessun rischio\": il contenuto rimasto cifrato non è stato esaminato.\n\n");
        findings.forEach(f -> text.append(f.ruleId()).append(" v").append(f.ruleVersion()).append(" · ").append(f.severity())
                .append(" · confidenza ").append(f.confidence()).append("\nRiferimento: ").append(f.evidenceKey())
                .append("\n").append(f.explanation()).append("\nVerifica: ").append(f.nextStep()).append("\n\n"));
        return text.toString();
    }
    private VBox settingsPane(Path db) {
        adbPath.disableProperty().bind(busy); tsharkPath.disableProperty().bind(busy);
        Label tools = new Label("Percorsi degli eseguibili, senza virgolette o argomenti. ADB e TShark devono essere installati separatamente."); tools.setWrapText(true);
        Button history = button("Carica ultimo inventario", () -> run("Lettura storico…", () -> repository.recent(1), list -> {
            if (list.isEmpty()) status.setText("Nessun inventario salvato.");
            else { showInventory(list.getFirst(), true); status.setText("Ultimo inventario caricato nella scheda Android. È una fotografia storica, non lo stato attuale."); }
        }));
        Button delete = button("Elimina tutti gli inventari salvati", () -> {
            Alert confirm = new Alert(Alert.AlertType.CONFIRMATION, "Eliminare tutti gli inventari locali? L'operazione non è annullabile.", ButtonType.CANCEL, ButtonType.OK);
            if (confirm.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) return;
            run("Eliminazione storico…", () -> { repository.deleteAll(); return true; }, ok -> { clearInventory(); status.setText("Storico locale eliminato."); });
        });
        Label privacy = new Label("Salvataggio solo su richiesta. SQLite contiene seriale, modello, data e nomi dei pacchetti in chiaro. Proteggi l'account del PC e usa la cifratura del disco se necessaria. I dati PCAP non vengono salvati nel database. La cancellazione non rimuove eventuali backup del sistema."); privacy.setWrapText(true);
        Label location = new Label("Database: " + db); location.setWrapText(true);
        Button savePaths = button("Salva percorsi", () -> {
            try {
                ToolSettings settings = new ToolSettings(tool(adbPath), tool(tsharkPath));
                run("Salvataggio percorsi…", () -> { settingsRepository.saveSettings(settings); return settings; },
                    saved -> status.setText("Percorsi salvati. Saranno caricati al prossimo avvio."));
            } catch (ScanException error) { status.setText(error.getMessage()); }
        });
        return pane(tools, new Label("ADB"), adbPath, new Label("TShark"), tsharkPath, savePaths, new Separator(), location, privacy, history, delete);
    }
    private void clearInventory() { inventory = null; apps.clear(); savable.set(false); inventoryLabel.setText("Nessun inventario acquisito"); }
    private void showInventory(Inventory value, boolean historical) {
        inventory = value; apps.setAll(value.apps()); savable.set(false);
        inventoryLabel.setText((historical ? "STORICO · " : "ACQUISIZIONE · ") + value.device().model() + " · " + value.device().serial() + " · " + value.collectedAt());
    }
    private static VBox pane(javafx.scene.Node... nodes) {
        for (var node : nodes) if (node instanceof Label label && label.isWrapText()) {
            label.setMinHeight(Region.USE_PREF_SIZE); label.setMaxWidth(Double.MAX_VALUE);
        }
        VBox box = new VBox(12, nodes); box.setPadding(new Insets(20)); return box;
    }
    private static String origin(InstalledApp app) {
        String installer = app.metadata().installer();
        if (!app.metadata().known()) return "metadati assenti";
        return switch (installer) {
            case "" -> "non registrata";
            case "com.android.vending", "com.google.android.feedback" -> "Google Play";
            case "com.sec.android.app.samsungapps", "com.samsung.android.app.appsstore" -> "Samsung Galaxy Store";
            case "org.fdroid.fdroid", "org.fdroid.basic" -> "F-Droid";
            case "com.amazon.venezia" -> "Amazon Appstore";
            default -> installer;
        };
    }
    private static <T> TableColumn<T,String> column(String title, Function<T,String> value, int width) {
        TableColumn<T,String> col = new TableColumn<>(title); col.setCellValueFactory(c -> new SimpleStringProperty(value.apply(c.getValue()))); col.setPrefWidth(width); return col;
    }
    private <T> void run(String message, Callable<T> work, Consumer<T> success) {
        if (busy.get()) return;
        busy.set(true); status.setText(message);
        Task<T> task = new Task<>() { @Override protected T call() throws Exception { return work.call(); } };
        active = task;
        task.setOnSucceeded(e -> { busy.set(false); active = null; success.accept(task.getValue()); });
        task.setOnFailed(e -> { busy.set(false); active = null; Throwable error = task.getException(); status.setText(error instanceof ScanException ? error.getMessage() : "Errore inatteso. Operazione non completata."); });
        task.setOnCancelled(e -> { busy.set(false); active = null; status.setText("Operazione annullata. Eventuali scritture già completate possono essere presenti nello storico."); });
        worker.submit(task);
    }
    @Override public void stop() { if (active != null) active.cancel(true); worker.shutdownNow(); }
}
