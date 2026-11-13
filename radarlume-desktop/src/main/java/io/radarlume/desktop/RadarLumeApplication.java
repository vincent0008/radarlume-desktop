package io.radarlume.desktop;

import io.radarlume.adb.AdbDeviceInspector;
import io.radarlume.application.DeviceScanService;
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
    private final ObservableList<NetworkFlow> flows = FXCollections.observableArrayList();
    private final BooleanProperty savable = new SimpleBooleanProperty();
    private final Label inventoryLabel = new Label("Nessun inventario acquisito");
    private final Label networkLabel = new Label("Nessuna cattura importata");
    private Inventory inventory;
    private Task<?> active;
    private InventoryRepository repository;

    @Override public void start(Stage stage) {
        Path db = Path.of(System.getProperty("radarlume.dataDir", Path.of(System.getProperty("user.home"), ".radarlume").toString()), "inventories.db");
        repository = new SqliteInventoryRepository(db);
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
        table.getColumns().add(column("Pacchetto", InstalledApp::packageName, 620));
        table.getColumns().add(column("Tipo", a -> a.system() ? "Sistema" : "Utente", 160));
        table.setPlaceholder(new Label("L'inventario apparirà qui dopo una lettura autorizzata."));
        Label note = new Label("Nomi tecnici dei pacchetti e classificazione sistema/utente. Nessuna analisi dei permessi o verdetto malware in questa versione."); note.setWrapText(true);
        VBox pane = pane(new HBox(12, discover, devices), consent, new HBox(12, scan, save), inventoryLabel, filter, table, note);
        VBox.setVgrow(table, Priority.ALWAYS); return pane;
    }
    private VBox networkPane(Stage stage) {
        Label note = new Label("Importa soltanto catture che sei autorizzato ad analizzare. Il collegamento USB non rende automaticamente visibile il traffico del telefono. Sono aggregati i pacchetti TCP/UDP IPv4/IPv6 per direzione, senza attribuzione alle app."); note.setWrapText(true);
        Button open = button("Importa PCAP / PCAPNG", () -> {
            FileChooser chooser = new FileChooser(); chooser.setTitle("Seleziona cattura autorizzata");
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Catture di rete", "*.pcap", "*.pcapng", "*.cap"));
            var file = chooser.showOpenDialog(stage); if (file == null) return;
            var analyzer = new TsharkTrafficAnalyzer(tool(tsharkPath), new BoundedProcessRunner(16 * 1024 * 1024));
            flows.clear(); networkLabel.setText("Nessuna analisi completata");
            run("Analisi cattura…", () -> analyzer.analyze(file.toPath()), list -> {
                flows.setAll(list); networkLabel.setText(file.getName() + " · " + list.size() + " flussi direzionali");
                status.setText(list.isEmpty() ? "Nessun pacchetto TCP/UDP IP decodificabile. Non è un giudizio di sicurezza." : "Importazione completata. Metadati in memoria; nessuna regola di rilevamento applicata.");
            });
        });
        TableView<NetworkFlow> table = new TableView<>(flows);
        table.getColumns().add(column("Sorgente", NetworkFlow::source, 220)); table.getColumns().add(column("Destinazione", NetworkFlow::destination, 220));
        table.getColumns().add(column("Protocollo", NetworkFlow::protocol, 90)); table.getColumns().add(column("Porta sorg.", NetworkFlow::sourcePort, 100));
        table.getColumns().add(column("Porta dest.", NetworkFlow::destinationPort, 100));
        table.getColumns().add(column("Pacchetti", f -> Long.toString(f.packets()), 90)); table.getColumns().add(column("Byte frame", f -> Long.toString(f.bytes()), 100));
        table.setPlaceholder(new Label("Nessuna cattura importata"));
        VBox pane = pane(note, open, networkLabel, table); VBox.setVgrow(table, Priority.ALWAYS); return pane;
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
        return pane(tools, new Label("ADB"), adbPath, new Label("TShark"), tsharkPath, new Separator(), location, privacy, history, delete);
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
