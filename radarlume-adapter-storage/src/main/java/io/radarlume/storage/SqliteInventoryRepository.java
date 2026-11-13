package io.radarlume.storage;

import io.radarlume.domain.*;
import java.nio.file.*;
import java.io.IOException;
import java.sql.*;
import java.time.Instant;
import java.util.*;

/** Opens one connection per operation. Schema v1 and inventory writes are transactional. */
public final class SqliteInventoryRepository implements InventoryRepository {
    private final Path file;
    public SqliteInventoryRepository(Path file) { this.file = file.toAbsolutePath(); }
    private Connection open() throws SQLException, IOException {
        Files.createDirectories(file.getParent());
        Connection c = DriverManager.getConnection("jdbc:sqlite:" + file);
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA foreign_keys=ON"); s.execute("PRAGMA busy_timeout=5000");
            s.execute("PRAGMA secure_delete=ON");
            int version;
            try (ResultSet r = s.executeQuery("PRAGMA user_version")) { version = r.getInt(1); }
            if (version > 1) throw new SQLException("Schema database più recente dell'applicazione");
            if (version == 0) {
                c.setAutoCommit(false);
                s.executeUpdate("CREATE TABLE IF NOT EXISTS inventories (id TEXT PRIMARY KEY, collected_at TEXT NOT NULL, serial TEXT NOT NULL, model TEXT NOT NULL)");
                s.executeUpdate("CREATE TABLE IF NOT EXISTS apps (inventory_id TEXT NOT NULL REFERENCES inventories(id) ON DELETE CASCADE, package_name TEXT NOT NULL, system INTEGER NOT NULL CHECK(system IN (0,1)), PRIMARY KEY(inventory_id,package_name))");
                s.execute("PRAGMA user_version=1"); c.commit(); c.setAutoCommit(true);
            }
            return c;
        } catch (SQLException | RuntimeException e) { c.close(); throw e; }
    }
    @Override public void save(Inventory inventory) {
        try (Connection c = open()) {
            c.setAutoCommit(false);
            try (PreparedStatement scan = c.prepareStatement("INSERT INTO inventories VALUES(?,?,?,?)");
                 PreparedStatement app = c.prepareStatement("INSERT INTO apps VALUES(?,?,?)")) {
                scan.setString(1, inventory.id().toString()); scan.setString(2, inventory.collectedAt().toString());
                scan.setString(3, inventory.device().serial()); scan.setString(4, inventory.device().model()); scan.executeUpdate();
                for (InstalledApp item : inventory.apps()) {
                    app.setString(1, inventory.id().toString()); app.setString(2, item.packageName()); app.setInt(3, item.system() ? 1 : 0); app.addBatch();
                }
                app.executeBatch(); c.commit();
            } catch (SQLException e) { c.rollback(); throw e; }
        } catch (SQLException | IOException e) { throw new ScanException("Salvataggio locale non riuscito. L'inventario resta disponibile in memoria.", e); }
    }
    @Override public List<Inventory> recent(int limit) {
        if (limit < 1 || limit > 100) throw new IllegalArgumentException("Limite storico: 1–100");
        if (!Files.exists(file)) return List.of();
        try (Connection c = open(); PreparedStatement query = c.prepareStatement("SELECT * FROM inventories ORDER BY collected_at DESC LIMIT ?")) {
            query.setInt(1, limit);
            var result = new ArrayList<Inventory>();
            try (ResultSet r = query.executeQuery(); PreparedStatement apps = c.prepareStatement("SELECT * FROM apps WHERE inventory_id=? ORDER BY package_name")) {
                while (r.next()) {
                    apps.setString(1, r.getString("id"));
                    var items = new ArrayList<InstalledApp>();
                    try (ResultSet a = apps.executeQuery()) { while (a.next()) items.add(new InstalledApp(a.getString("package_name"), a.getInt("system") == 1)); }
                    result.add(new Inventory(UUID.fromString(r.getString("id")), Instant.parse(r.getString("collected_at")),
                            new Device(r.getString("serial"), Device.State.AUTHORIZED, r.getString("model")), items));
                }
            }
            return List.copyOf(result);
        } catch (SQLException | IOException | IllegalArgumentException e) { throw new ScanException("Impossibile leggere lo storico locale.", e); }
    }
    @Override public void deleteAll() {
        if (!Files.exists(file)) return;
        try (Connection c = open(); Statement s = c.createStatement()) { s.executeUpdate("DELETE FROM inventories"); s.execute("VACUUM"); }
        catch (SQLException | IOException e) { throw new ScanException("Eliminazione dello storico non riuscita.", e); }
    }
}
