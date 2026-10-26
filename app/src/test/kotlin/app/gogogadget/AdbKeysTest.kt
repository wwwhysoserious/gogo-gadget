package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.security.KeyStoreException
import java.security.interfaces.RSAPrivateCrtKey
import javax.crypto.AEADBadTagException
import java.security.interfaces.RSAPublicKey
import java.security.cert.X509Certificate

class AdbKeysTest {
    @Test fun generatedIdentityIsRsa2048WithAMatchingSelfSignedCertificate() {
        val identity = generateAdbIdentity()
        val cert = identity.certificate as X509Certificate
        val pub = cert.publicKey as RSAPublicKey
        val priv = identity.privateKey as RSAPrivateCrtKey
        assertEquals(2048, pub.modulus.bitLength())
        assertEquals(pub.modulus, priv.modulus)
        cert.verify(pub) // self-signed: throws if the signature does not match
        cert.checkValidity()
        assertTrue(cert.subjectX500Principal.name.contains("GoGo Gadget"))
    }

    @Test fun onlyAPermanentlyLostKeyIsRegenerated() {
        assertTrue(isKeyGone(AEADBadTagException("tag mismatch")))
        assertTrue(isKeyGone(RuntimeException("wrapped", AEADBadTagException())))
        assertFalse(isKeyGone(KeyStoreException("keystore busy")))
        assertFalse(isKeyGone(IOException("unreadable")))
        assertFalse(isKeyGone(RuntimeException("other")))
    }
}
