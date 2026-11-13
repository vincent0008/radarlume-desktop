package io.radarlume.desktop;

/** Separate launcher supports JavaFX on the classpath. */
public final class Launcher {
    private Launcher() {}
    public static void main(String[] args) { javafx.application.Application.launch(RadarLumeApplication.class, args); }
}
