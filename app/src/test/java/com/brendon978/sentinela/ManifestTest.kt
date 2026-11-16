package com.brendon978.sentinela

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ManifestTest {
    private val manifest = File("src/main/AndroidManifest.xml").readText()

    /** O Nubank bloqueou a conta quando o launcher usava acessibilidade: aqui ela nunca entra. */
    @Test fun naoDeclaraAcessibilidadeNemSobreposicao() {
        assertFalse(manifest.contains("BIND_ACCESSIBILITY_SERVICE"))
        assertFalse(manifest.contains("SYSTEM_ALERT_WINDOW"))
    }

    @Test fun servicoDeVpnProtegidoEDeclarado() {
        assertTrue(manifest.contains("android.permission.BIND_VPN_SERVICE"))
        assertTrue(manifest.contains("android.net.VpnService"))
        assertTrue(manifest.contains("FOREGROUND_SERVICE_SYSTEM_EXEMPTED"))
        assertTrue(manifest.contains("systemExempted"))
    }
}
