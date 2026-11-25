package io.deltator.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class LocalProxyAuthTest {

    @Test
    fun testRejectNoAuthByDefault() {
        val methods = byteArrayOf(0x00) // Client offers only NO_AUTH
        val input = ByteArrayInputStream(byteArrayOf())
        val output = ByteArrayOutputStream()

        val result = LocalProxyAuth.handleGreeting(
            methods = methods,
            input = input,
            output = output,
            username = null,
            password = null,
            allowNoAuth = false
        )

        assertFalse(result)
        // Should respond with 0x05, 0xFF (no acceptable methods)
        assertArrayEquals(byteArrayOf(0x05, 0xFF.toByte()), output.toByteArray())
    }

    @Test
    fun testAllowNoAuthWhenExplicitlyEnabled() {
        val methods = byteArrayOf(0x00)
        val input = ByteArrayInputStream(byteArrayOf())
        val output = ByteArrayOutputStream()

        val result = LocalProxyAuth.handleGreeting(
            methods = methods,
            input = input,
            output = output,
            username = null,
            password = null,
            allowNoAuth = true
        )

        assertTrue(result)
        assertArrayEquals(byteArrayOf(0x05, 0x00), output.toByteArray())
    }

    @Test
    fun testSuccessfulPasswordAuth() {
        val methods = byteArrayOf(0x00, 0x02) // NO_AUTH and USERNAME/PASSWORD
        val username = "testuser"
        val password = "secretpassword"

        // Client subnegotiation payload: [0x01 (authVer), uLen, userBytes..., pLen, passBytes...]
        val subneg = ByteArrayOutputStream().apply {
            write(0x01)
            write(username.length)
            write(username.toByteArray(Charsets.UTF_8))
            write(password.length)
            write(password.toByteArray(Charsets.UTF_8))
        }.toByteArray()

        val input = ByteArrayInputStream(subneg)
        val output = ByteArrayOutputStream()

        val result = LocalProxyAuth.handleGreeting(
            methods = methods,
            input = input,
            output = output,
            username = username,
            password = password
        )

        assertTrue(result)
        // Output should be: [0x05, 0x02] (select method 0x02), then [0x01, 0x00] (auth success)
        assertArrayEquals(byteArrayOf(0x05, 0x02, 0x01, 0x00), output.toByteArray())
    }

    @Test
    fun testWrongPasswordRejected() {
        val methods = byteArrayOf(0x02)
        val username = "testuser"
        val password = "correctpassword"
        val wrongPass = "wrongpassword"

        val subneg = ByteArrayOutputStream().apply {
            write(0x01)
            write(username.length)
            write(username.toByteArray(Charsets.UTF_8))
            write(wrongPass.length)
            write(wrongPass.toByteArray(Charsets.UTF_8))
        }.toByteArray()

        val input = ByteArrayInputStream(subneg)
        val output = ByteArrayOutputStream()

        val result = LocalProxyAuth.handleGreeting(
            methods = methods,
            input = input,
            output = output,
            username = username,
            password = password
        )

        assertFalse(result)
        // Output should be: [0x05, 0x02], then [0x01, 0x01] (auth failure)
        assertArrayEquals(byteArrayOf(0x05, 0x02, 0x01, 0x01), output.toByteArray())
    }

    @Test
    fun testGenerateSessionCredentialsProducesValidHex() {
        val (user, pass) = LocalProxyAuth.generateSessionCredentials()
        assertEquals(32, user.length)
        assertEquals(32, pass.length)
        assertTrue(user.all { it in '0'..'9' || it in 'a'..'f' })
        assertTrue(pass.all { it in '0'..'9' || it in 'a'..'f' })
    }
}
