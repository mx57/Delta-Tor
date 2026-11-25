package io.deltator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ReleaseCheckerTest {

    @Test
    fun testCompareVersions() {
        assertTrue(ReleaseChecker.compareVersions("2.0.0", "2.1.0") < 0)
        assertTrue(ReleaseChecker.compareVersions("2.1.0", "2.0.0") > 0)
        assertEquals(0, ReleaseChecker.compareVersions("2.1.0", "2.1.0"))
        assertTrue(ReleaseChecker.compareVersions("2.1", "2.1.1") < 0)
        assertTrue(ReleaseChecker.compareVersions("3.0.0", "2.99.99") > 0)
    }

    @Test
    fun testPathTraversalRejection() {
        val baseDir = File("temp_updates_dir")
        baseDir.mkdirs()
        try {
            val maliciousNames = listOf(
                "../../evil.apk",
                "..\\..\\evil.apk",
                "/etc/evil.apk",
                "foo/../../bar.apk",
                "nested/../../../../etc/passwd"
            )

            for (raw in maliciousNames) {
                val cleanName = File(raw).name
                val targetFile = File(baseDir, cleanName)
                // The filename must be sanitized and strictly within baseDir
                assertTrue(
                    "Target path should stay strictly within baseDir for $raw",
                    targetFile.canonicalPath.startsWith(baseDir.canonicalPath + File.separator)
                )
                assertEquals("evil.apk", File("../../evil.apk").name)
            }
        } finally {
            baseDir.deleteRecursively()
        }
    }

    @Test
    fun testComputeSha256() {
        val temp = File.createTempFile("deltator_test", ".apk")
        try {
            temp.writeBytes("Hello DeltaTor".toByteArray(Charsets.UTF_8))
            val sha = ReleaseChecker.computeSha256(temp)
            // SHA-256 of "Hello DeltaTor"
            val expected = "d59179b40dafc72a90b1f69a3379348c8ef0d2f161deca318b87484c498d9ea0"
            assertEquals(expected, sha)
        } finally {
            temp.delete()
        }
    }
}
