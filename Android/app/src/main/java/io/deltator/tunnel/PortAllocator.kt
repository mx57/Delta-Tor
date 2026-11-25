package io.deltator.tunnel

import io.deltator.util.AppLog as Log
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.Collections

/**
 * Centralized thread-safe port allocator with collision detection and retry logic.
 *
 * Prevents port race conditions between concurrent Tor runners, snowflake/dnstt
 * pluggable transports, and local SOCKS/control ports.
 */
object PortAllocator {
    private const val TAG = "PortAllocator"
    private const val DEFAULT_RETRIES = 30

    private val allocatedPorts = Collections.synchronizedSet(mutableSetOf<Int>())

    /**
     * Allocate a free ephemeral port on [host], ensuring it does not collide with
     * any currently allocated port in the process.
     */
    fun allocateFreePort(host: String = "127.0.0.1", maxAttempts: Int = DEFAULT_RETRIES): Int {
        synchronized(allocatedPorts) {
            for (attempt in 1..maxAttempts) {
                val candidate = try {
                    ServerSocket().use { socket ->
                        socket.reuseAddress = false
                        socket.bind(InetSocketAddress(host, 0))
                        socket.localPort
                    }
                } catch (e: Exception) {
                    Log.d(TAG, "Attempt $attempt to probe free port on $host failed: ${e.message}")
                    continue
                }

                if (candidate > 0 && !allocatedPorts.contains(candidate)) {
                    allocatedPorts.add(candidate)
                    Log.d(TAG, "Allocated free ephemeral port $candidate on $host (total allocated: ${allocatedPorts.size})")
                    return candidate
                }
            }
            throw IllegalStateException("Failed to allocate a free ephemeral port on $host after $maxAttempts attempts")
        }
    }

    /**
     * Explicitly reserve a known port (e.g. static configuration).
     * Returns true if successfully reserved, false if already reserved.
     */
    fun reserve(port: Int): Boolean {
        return synchronized(allocatedPorts) {
            allocatedPorts.add(port)
        }
    }

    /**
     * Release a previously allocated port back to the system pool.
     */
    fun release(port: Int) {
        if (port <= 0) return
        val removed = allocatedPorts.remove(port)
        if (removed) {
            Log.d(TAG, "Released port $port (remaining allocated: ${allocatedPorts.size})")
        }
    }

    /**
     * Clear all tracked allocations (used during full service teardown).
     */
    fun clear() {
        val count = allocatedPorts.size
        allocatedPorts.clear()
        Log.d(TAG, "Cleared $count tracked port allocations")
    }
}
