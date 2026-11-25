package io.deltator.tunnel

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BridgeLineValidatorTest {

    @Test
    fun testValidObfs4Bridge() {
        val validObfs4 = "obfs4 192.0.2.1:443 7F8E3B6899738A5F35409E2B2A2FA6F7524A2201 cert=477K9o... iat-mode=0"
        assertTrue(BridgeLineValidator.isValidBridgeLine(validObfs4))
    }

    @Test
    fun testValidWebtunnelBridge() {
        val validWebtunnel = "webtunnel 192.0.2.2:443 7F8E3B6899738A5F35409E2B2A2FA6F7524A2201 url=https://example.com/path"
        assertTrue(BridgeLineValidator.isValidBridgeLine(validWebtunnel))
    }

    @Test
    fun testValidVanillaBridge() {
        val validVanilla = "192.0.2.3:9001 7F8E3B6899738A5F35409E2B2A2FA6F7524A2201"
        assertTrue(BridgeLineValidator.isValidBridgeLine(validVanilla))
    }

    @Test
    fun testValidIpv6Bridge() {
        val validIpv6 = "obfs4 [2001:db8::1]:443 7F8E3B6899738A5F35409E2B2A2FA6F7524A2201 cert=xxx iat-mode=0"
        assertTrue(BridgeLineValidator.isValidBridgeLine(validIpv6))
    }

    @Test
    fun testRejectDirectiveInjectionWithNewline() {
        val malicious = "obfs4 192.0.2.1:443 7F8E3B6899738A5F35409E2B2A2FA6F7524A2201\nControlPort 0.0.0.0:9051"
        assertFalse(BridgeLineValidator.isValidBridgeLine(malicious))
    }

    @Test
    fun testRejectCarriageReturnInjection() {
        val malicious = "obfs4 192.0.2.1:443 7F8E3B6899738A5F35409E2B2A2FA6F7524A2201\rControlPort 0.0.0.0:9051"
        assertFalse(BridgeLineValidator.isValidBridgeLine(malicious))
    }

    @Test
    fun testRejectNullByteInjection() {
        val malicious = "obfs4 192.0.2.1:443\u0000ControlPort 0.0.0.0:9051"
        assertFalse(BridgeLineValidator.isValidBridgeLine(malicious))
    }

    @Test
    fun testRejectForbiddenDirectivesInTokens() {
        val malicious = "obfs4 192.0.2.1:443 ControlPort 0.0.0.0:9051"
        assertFalse(BridgeLineValidator.isValidBridgeLine(malicious))
    }

    @Test
    fun testRejectCommentsAndEmpty() {
        assertFalse(BridgeLineValidator.isValidBridgeLine(""))
        assertFalse(BridgeLineValidator.isValidBridgeLine("   "))
        assertFalse(BridgeLineValidator.isValidBridgeLine("# this is a comment"))
    }
}
