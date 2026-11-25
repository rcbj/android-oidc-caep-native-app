// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.net.URI

/**
 * [WebAuthenticator] for a loopback redirect URI (RFC 8252 §7.3), such as `http://127.0.0.1:53682/callback`: it
 * listens on that port, opens the provider's page with [openBrowser], and returns when the browser is redirected
 * back to the port.
 *
 * On Android prefer [CustomTabsWebAuthenticator] with a private-use scheme. This one serves tests (where
 * [openBrowser] walks the provider's pages over HTTP) and apps that must use a loopback redirect.
 */
public class LoopbackWebAuthenticator(
    /** How long to wait for the browser to come back (seconds). */
    public val timeoutSeconds: Double = 300.0,
    private val openBrowser: suspend (URI) -> Unit,
) : WebAuthenticator {
    override suspend fun authenticate(url: URI, callback: URI): URI {
        if (callback.scheme?.lowercase() != "http" || !isLoopback(callback) || callback.port == -1) {
            throw OIDCError.usage("LoopbackWebAuthenticator needs a loopback redirect URI with a port, such as http://127.0.0.1:53682/callback, not $callback")
        }
        val host = if (callback.host == "localhost") "127.0.0.1" else callback.host.trim('[', ']')
        val port = callback.port
        // A sign-in that never came back (the provider showed an error and never redirected, the tab was closed)
        // still holds the port until it times out. A new one on the same port replaces it: the old one ends as
        // cancelled, and its socket is closed before this one binds.
        val replaced = synchronized(active) { active.remove(port) }
        replaced?.cancel()
        val listener = withContext(Dispatchers.IO) { Listener.bindRetrying(host, port, if (replaced == null) 0L else 2000L) }
        synchronized(active) { active[port] = listener }
        val server = listener.server
        try {
            try {
                openBrowser(url)
            } catch (e: Exception) {
                throw OIDCError(OIDCError.Kind.GENERAL, "Could not open the browser: ${e.message}", code = "web_authentication_failed", cause = e)
            }
            val path = callback.rawPath?.ifEmpty { "/" } ?: "/"
            val deadline = System.currentTimeMillis() + (timeoutSeconds * 1000).toLong()
            val query = runInterruptible(Dispatchers.IO) { waitForRequest(listener, path, deadline) }
            return URI(callback.scheme, null, callback.host, callback.port, callback.path, null, null).let { base ->
                if (query.isEmpty()) base else URI("$base?$query")
            }
        } finally {
            withContext(Dispatchers.IO) { runCatching { server.close() } }
            synchronized(active) { if (active[port] === listener) active.remove(port) }
        }
    }

    /** One listening socket on a loopback port. */
    private class Listener(val server: ServerSocket) {
        @Volatile var cancelled = false

        /** Stops waiting, and frees the port. */
        fun cancel() {
            cancelled = true
            runCatching { server.close() }
        }

        companion object {
            /** Binds, retrying for up to [retryForMillis] while the port is still held by a listener being replaced. */
            fun bindRetrying(host: String, port: Int, retryForMillis: Long): Listener {
                val deadline = System.currentTimeMillis() + retryForMillis
                while (true) {
                    try {
                        return Listener(ServerSocket().apply {
                            reuseAddress = true
                            bind(InetSocketAddress(InetAddress.getByName(host), port), 8)
                        })
                    } catch (e: IOException) {
                        if (System.currentTimeMillis() >= deadline) {
                            throw OIDCError(OIDCError.Kind.GENERAL, "Loopback redirect listener failed (listening on port $port): ${e.message}",
                                code = "web_authentication_failed", cause = e)
                        }
                        Thread.sleep(50)
                    }
                }
            }
        }
    }

    private companion object {
        /** The listener waiting on each port, in this process. */
        val active = HashMap<Int, Listener>()
    }

    /** Answers requests until one arrives for [path], and returns its query string. */
    private fun waitForRequest(listener: Listener, path: String, deadline: Long): String {
        val server = listener.server
        server.soTimeout = 250
        while (true) {
            if (Thread.interrupted() || listener.cancelled) throw OIDCError(OIDCError.Kind.GENERAL, "The sign-in was cancelled", code = OIDCError.USER_CANCELLED_CODE)
            if (System.currentTimeMillis() > deadline) {
                throw OIDCError(OIDCError.Kind.GENERAL, "The browser did not come back within the time allowed", code = "web_authentication_failed")
            }
            val client = try { server.accept() } catch (e: SocketTimeoutException) { continue } catch (e: IOException) {
                if (listener.cancelled) throw OIDCError(OIDCError.Kind.GENERAL, "The sign-in was cancelled", code = OIDCError.USER_CANCELLED_CODE)
                throw OIDCError(OIDCError.Kind.GENERAL, "Loopback redirect listener failed: ${e.message}", code = "web_authentication_failed", cause = e)
            }
            client.use { socket ->
                socket.soTimeout = 5000
                val target = readRequestTarget(socket.getInputStream()) ?: return@use
                val parts = target.split("?", limit = 2)
                val out = socket.getOutputStream()
                if (parts[0] != path) {
                    respond(out, "404 Not Found", "Not found.")
                    return@use
                }
                respond(out, "200 OK", "Signed in. You can close this window and return to the app.")
                return if (parts.size > 1) parts[1] else ""
            }
        }
    }

    /** The request target of an HTTP/1.x GET (`/callback?code=…`). */
    private fun readRequestTarget(input: java.io.InputStream): String? {
        val data = StringBuilder()
        val buffer = ByteArray(4096)
        while (data.length < 65_536 && !data.contains("\r\n\r\n")) {
            val n = try { input.read(buffer) } catch (e: IOException) { -1 }
            if (n <= 0) break
            data.append(String(buffer, 0, n, Charsets.ISO_8859_1))
        }
        val fields = data.lineSequence().firstOrNull()?.trim()?.split(" ") ?: return null
        if (fields.size != 3 || fields[0] != "GET" || !fields[2].startsWith("HTTP/1.")) return null
        return fields[1]
    }

    private fun respond(out: java.io.OutputStream, status: String, body: String) {
        val html = "<!doctype html><meta charset=utf-8><title>$body</title><p style=\"font:16px sans-serif;margin:3em\">$body</p>"
        val bytes = html.encodeToByteArray()
        out.write(("HTTP/1.1 $status\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${bytes.size}\r\nCache-Control: no-store\r\n" +
            "Referrer-Policy: no-referrer\r\nConnection: close\r\n\r\n").encodeToByteArray() + bytes)
        out.flush()
    }
}

