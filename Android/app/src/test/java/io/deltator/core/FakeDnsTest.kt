package io.deltator.core

import io.deltator.core.dns.FakeDns
import io.deltator.feature.amnezia.AmneziaConfig
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class FakeDnsTest {

    @Before
    fun setUp() {
        FakeDns.clear()
        FakeDns.enabled = true
    }

    @Test
    fun testParseStandardDomainName() {
        // "example.com" in DNS wire format: 7 "example" 3 "com" 0
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(7))
        out.write("example".toByteArray())
        out.write(byteArrayOf(3))
        out.write("com".toByteArray())
        out.write(byteArrayOf(0))

        val bytes = out.toByteArray()
        val parsed = FakeDns.parseDomainName(bytes, 0)
        assertNotNull(parsed)
        assertEquals("example.com", parsed!!.first)
        assertEquals(bytes.size, parsed.second)
    }

    @Test
    fun testParseCompressionPointer() {
        // Simulate a DNS packet where at offset 12 is "target.org",
        // and at offset 30 is a label pointing to offset 12 via 0xC00C
        val buf = ByteArray(40)
        // Offset 12: 6 "target" 3 "org" 0
        var pos = 12
        buf[pos++] = 6
        System.arraycopy("target".toByteArray(), 0, buf, pos, 6)
        pos += 6
        buf[pos++] = 3
        System.arraycopy("org".toByteArray(), 0, buf, pos, 3)
        pos += 3
        buf[pos++] = 0

        // Offset 30: 0xC00C (pointer to offset 12)
        buf[30] = 0xC0.toByte()
        buf[31] = 12.toByte()

        val parsed = FakeDns.parseDomainName(buf, 30)
        assertNotNull(parsed)
        assertEquals("target.org", parsed!!.first)
        assertEquals(32, parsed.second)
    }

    @Test
    fun testCompressionPointerLoopProtection() {
        // Create an infinite loop: pointer at offset 20 points to offset 20
        val buf = ByteArray(30)
        buf[20] = 0xC0.toByte()
        buf[21] = 20.toByte()

        val parsed = FakeDns.parseDomainName(buf, 20)
        // Must reject cycle and return null
        assertNull(parsed)
    }

    @Test
    fun testLruAndSyntheticIpAllocation() {
        val ip1 = FakeDns.getOrAllocateIp("site1.com")
        val ip2 = FakeDns.getOrAllocateIp("site2.com")
        assertTrue(FakeDns.isFakeIp(ip1))
        assertTrue(FakeDns.isFakeIp(ip2))
        assertNotEquals(ip1, ip2)

        // Reverse lookup
        assertEquals("site1.com", FakeDns.getDomain(ip1))
        assertEquals("site2.com", FakeDns.getDomain(ip2))

        // Same domain returns same IP
        assertEquals(ip1, FakeDns.getOrAllocateIp("site1.com"))
    }

    @Test
    fun testAmneziaConfigParsingWithCommentsAndHex() {
        val conf = """
            # Global config comment
            [Interface]
            PrivateKey = aaaaaa= ; inline semicolon comment
            Address = 10.8.0.5/24 # inline hash comment
            DNS = 8.8.8.8
            Jc = 8 # junk packet count
            H1 = 0x12345678 ; hex value
            H2 = 0x23456789
            H3 = 0x3456789A
            H4 = 0x456789AB

            [Peer]
            PublicKey = bbbbbb=
            Endpoint = 198.51.100.2:51820 # endpoint comment
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val parsed = AmneziaConfig.parseConf(conf)
        assertEquals("aaaaaa=", parsed.privateKey)
        assertEquals("10.8.0.5/24", parsed.address)
        assertEquals("8.8.8.8", parsed.dns)
        assertEquals(8, parsed.jc)
        assertEquals(0x12345678L, parsed.h1)
        assertEquals(0x23456789L, parsed.h2)
        assertEquals(0x3456789AL, parsed.h3)
        assertEquals(0x456789ABL, parsed.h4)
        assertEquals("bbbbbb=", parsed.peerPublicKey)
        assertEquals("198.51.100.2:51820", parsed.endpoint)
        assertTrue(parsed.validate())
    }
}
