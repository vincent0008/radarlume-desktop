package io.radarlume;
import io.radarlume.domain.*;
import io.radarlume.storage.SqliteInventoryRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.sql.*;
import static org.junit.jupiter.api.Assertions.*;
class SettingsIT {
    @TempDir Path dir;
    @Test void savesUpdatesAndKeepsSettingsWhenHistoryDeleted() {
        Path file=dir.resolve("data.db"); var repo=new SqliteInventoryRepository(file);
        assertTrue(repo.loadSettings().isEmpty()); assertFalse(Files.exists(file));
        repo.saveSettings(new ToolSettings("C:\\Tools with spaces\\adb.exe","tshark"));
        assertEquals("C:\\Tools with spaces\\adb.exe",new SqliteInventoryRepository(file).loadSettings().orElseThrow().adb());
        repo.saveSettings(new ToolSettings("adb","new-tshark")); repo.deleteAll();
        assertEquals("new-tshark",repo.loadSettings().orElseThrow().tshark());
    }
    @Test void migratesV1WithoutLosingInventory() throws Exception {
        Path file=dir.resolve("old.db");
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+file);var s=c.createStatement()) {
            s.execute("CREATE TABLE inventories(id TEXT PRIMARY KEY,collected_at TEXT,serial TEXT,model TEXT)");
            s.execute("CREATE TABLE apps(inventory_id TEXT,package_name TEXT,system INTEGER)");
            s.execute("INSERT INTO inventories VALUES('11111111-1111-1111-1111-111111111111','2026-01-01T00:00:00Z','test','test')");
            s.execute("PRAGMA user_version=1");
        }
        var repo=new SqliteInventoryRepository(file);repo.saveSettings(new ToolSettings("adb","tshark"));
        assertEquals(1,repo.recent(10).size());
    }
    @Test void rejectsInvalidSettings() {
        assertThrows(ScanException.class,()->new ToolSettings(" ","tshark"));
        assertThrows(ScanException.class,()->new ToolSettings("adb\n","tshark"));
    }
}
