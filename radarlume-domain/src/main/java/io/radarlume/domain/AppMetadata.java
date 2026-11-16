package io.radarlume.domain;

import java.util.List;

/**
 * Metadati di un pacchetto Android letti da {@code dumpsys package}: versione, origine di installazione
 * e permessi. La raccolta è best-effort e dipende dalla versione di Android; quando un dato manca si usa
 * {@link #UNKNOWN} o un valore vuoto, mai un'inferenza. I permessi sono nomi, non valori: dire che un'app
 * ha un permesso non dimostra come lo usa.
 */
public record AppMetadata(String versionName, long versionCode, String installer,
                          List<String> requestedPermissions, List<String> grantedPermissions) {

    /** Nessun metadato disponibile (versione sconosciuta, origine ignota, nessun permesso letto). */
    public static final AppMetadata UNKNOWN = new AppMetadata("", -1L, "", List.of(), List.of());

    public AppMetadata {
        versionName = versionName == null ? "" : versionName.strip();
        installer = installer == null ? "" : installer.strip();
        requestedPermissions = List.copyOf(requestedPermissions);
        grantedPermissions = List.copyOf(grantedPermissions);
    }

    /** True se almeno un metadato è stato letto; false quando è equivalente a {@link #UNKNOWN}. */
    public boolean known() {
        return !versionName.isEmpty() || versionCode >= 0 || !installer.isEmpty()
                || !requestedPermissions.isEmpty() || !grantedPermissions.isEmpty();
    }

    /** True se tra i permessi concessi c'è quello indicato (per nome pieno o per suffisso, es. "CAMERA"). */
    public boolean hasGranted(String permission) {
        return grantedPermissions.stream().anyMatch(p -> p.equals(permission) || p.endsWith("." + permission));
    }
}
