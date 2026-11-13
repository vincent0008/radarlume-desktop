package io.radarlume.desktop;

import javafx.application.Platform;
import javafx.embed.swing.SwingFXUtils;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import javax.imageio.ImageIO;
import java.nio.file.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Opt-in: requires a graphical session. Does not invoke ADB or read user data. */
@EnabledIfSystemProperty(named = "radarlume.uiTests", matches = "true")
class DesktopSmokeTest {
    @Test void opensAllScreensAndRendersWithoutDeviceAccess() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        Platform.startup(ready::countDown); assertTrue(ready.await(10, TimeUnit.SECONDS));
        FutureTask<Void> test = new FutureTask<>(() -> {
            var app = new RadarLumeApplication(); var stage = new Stage();
            try {
                app.start(stage); assertTrue(stage.isShowing());
                var scene = stage.getScene(); var root = scene.getRoot();
                root.applyCss(); root.layout();
                TabPane tabs = (TabPane) root.lookup(".tab-pane");
                assertEquals(3, tabs.getTabs().size());
                Button scan = root.lookupAll(".button").stream().filter(Button.class::isInstance).map(Button.class::cast)
                        .filter(b -> b.getText().equals("Leggi inventario")).findFirst().orElseThrow();
                assertTrue(scan.isDisabled(), "Scan must require both selected device and consent");
                Path screenshots = Path.of("target/ui-smoke"); Files.createDirectories(screenshots);
                for (int i = 0; i < tabs.getTabs().size(); i++) {
                    tabs.getSelectionModel().select(i); root.applyCss(); root.layout();
                    ImageIO.write(SwingFXUtils.fromFXImage(scene.snapshot(null), null), "png", screenshots.resolve("screen-" + i + ".png").toFile());
                }
            } finally { app.stop(); stage.close(); }
            return null;
        });
        Platform.runLater(test);
        try { test.get(30, TimeUnit.SECONDS); } finally { Platform.exit(); }
    }
}
