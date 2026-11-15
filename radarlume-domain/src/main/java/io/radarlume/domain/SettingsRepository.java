package io.radarlume.domain;
import java.util.Optional;
public interface SettingsRepository {
    Optional<ToolSettings> loadSettings();
    void saveSettings(ToolSettings settings);
}
