package io.radarlume.application;

/**
 * Template dello script Frida di unpinning. Neutralizza le verifiche di certificato e il pinning più
 * comuni su Android (TrustManagerImpl di Conscrypt, TrustManager passati a SSLContext.init, OkHttp3
 * CertificatePinner). Non è garantito: pinning nativo in C/C++, offuscamento e anti-Frida possono
 * renderlo inefficace. È pensato per analisi autorizzata su app e dispositivi di cui si ha il controllo.
 */
final class UnpinningScripts {
    private UnpinningScripts() {}

    static final String FRIDA_FILE_NAME = "radarlume-unpin.js";

    private static final String FRIDA_TEMPLATE = """
            /*
             * RadarLume - unpinning TLS per analisi forense autorizzata.
             * Pacchetto bersaglio: __PKG__
             * Uso consentito solo su app e dispositivi di cui si ha pieno controllo.
             * Neutralizza le verifiche di certificato/pinning piu' comuni su Android.
             * Non garantito: pinning nativo, offuscamento e anti-Frida possono renderlo inefficace.
             */
            Java.perform(function () {
                var TAG = '[RadarLume __PKG__]';

                function tryHook(name, fn) {
                    try { fn(); console.log(TAG + ' attivo: ' + name); }
                    catch (e) { console.log(TAG + ' non applicabile: ' + name + ' (' + e + ')'); }
                }

                // 1) Conscrypt / Android: il cuore del pinning di sistema.
                tryHook('TrustManagerImpl (Conscrypt)', function () {
                    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                    var ArrayList = Java.use('java.util.ArrayList');
                    if (TrustManagerImpl.checkTrustedRecursive) {
                        TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                            return ArrayList.$new();
                        };
                    }
                    if (TrustManagerImpl.verifyChain) {
                        TrustManagerImpl.verifyChain.implementation = function (untrustedChain) {
                            return untrustedChain;
                        };
                    }
                });

                // 2) TrustManager personalizzati passati a SSLContext.init -> sostituiti con uno permissivo.
                tryHook('SSLContext.init', function () {
                    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                    var SSLContext = Java.use('javax.net.ssl.SSLContext');
                    var Permissive = Java.registerClass({
                        name: 'io.radarlume.PermissiveTrustManager',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function () {},
                            checkServerTrusted: function () {},
                            getAcceptedIssuers: function () { return []; }
                        }
                    });
                    var init = SSLContext.init.overload(
                        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
                    init.implementation = function (km, tm, sr) {
                        init.call(this, km, [Permissive.$new()], sr);
                    };
                });

                // 3) OkHttp3: pinning esplicito via CertificatePinner.
                tryHook('OkHttp3 CertificatePinner', function () {
                    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                    var overloads = CertificatePinner.check.overloads;
                    for (var i = 0; i < overloads.length; i++) {
                        overloads[i].implementation = function () { return; };
                    }
                });

                console.log(TAG + ' script caricato. Avvia il traffico dell\\'app e cattura con PCAPdroid.');
            });
            """;

    /** Script pronto per il pacchetto indicato. Il nome è già validato dal servizio chiamante. */
    static String frida(String packageName) {
        return FRIDA_TEMPLATE.replace("__PKG__", packageName);
    }
}
