package io.deltator.feature.warp

import android.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WarpRegistrarTest {

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        val result = ByteArray(clean.length / 2)
        for (i in result.indices) {
            result[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    @Test
    fun testRfc7748AliceTestVector() {
        // RFC 7748 Section 6.1 Test Vectors for X25519
        // Alice private key: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
        val alicePriv = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val expectedAlicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

        val derivedPub = WarpRegistrar.derivePublicKey(alicePriv)
        assertEquals(expectedAlicePub, bytesToHex(derivedPub))
    }

    @Test
    fun testRfc7748BobTestVector() {
        // Bob private key: 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
        val bobPriv = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val expectedBobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

        val derivedPub = WarpRegistrar.derivePublicKey(bobPriv)
        assertEquals(expectedBobPub, bytesToHex(derivedPub))
    }

    @Test
    fun testClampPrivateKeyBits() {
        val raw = ByteArray(32) { 0xFF.toByte() }
        val clamped = WarpRegistrar.clampPrivateKey(raw)

        // Lowest 3 bits of clamped[0] must be 0
        assertEquals(0, (clamped[0].toInt() and 0x07))
        // Highest bit of clamped[31] must be 0
        assertEquals(0, (clamped[31].toInt() and 0x80))
        // Second highest bit of clamped[31] must be 1 (0x40)
        assertEquals(0x40, (clamped[31].toInt() and 0x40))
    }

    @Test
    fun testGenerateKeyPairClamping() {
        val (privB64, pubB64) = WarpRegistrar.generateKeyPair()
        val privBytes = java.util.Base64.getDecoder().decode(privB64)
        val pubBytes = java.util.Base64.getDecoder().decode(pubB64)

        assertEquals(32, privBytes.size)
        assertEquals(32, pubBytes.size)

        // Verify clamped bits directly on the exported private key
        assertEquals(0, (privBytes[0].toInt() and 0x07))
        assertEquals(0, (privBytes[31].toInt() and 0x80))
        assertEquals(0x40, (privBytes[31].toInt() and 0x40))

        // Verify that public key matches derivation from this private key
        val expectedPub = WarpRegistrar.derivePublicKey(privBytes)
        assertArrayEquals(expectedPub, pubBytes)
    }
}
