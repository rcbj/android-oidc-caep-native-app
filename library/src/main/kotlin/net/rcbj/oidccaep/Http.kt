// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** One HTTP request the library makes. Header names are lower case. */
public class HttpRequest(
    public val url: URI,
    public val method: String = "GET",
    headers: Map<String, String> = emptyMap(),
    public val body: ByteArray? = null,
) {
    public val headers: Map<String, String> = headers.mapKeys { it.key.lowercase() }
}

/** One HTTP response. Header names are lower case. */
public class HttpResponse(
    public val url: URI,
    public val status: Int,
    headers: Map<String, String> = emptyMap(),
    public val body: ByteArray = ByteArray(0),
) {
    public val headers: Map<String, String> = headers.mapKeys { it.key.lowercase() }
    public val isOK: Boolean get() = status in 200..299
    public fun header(name: String): String? = headers[name.lowercase()]
    public val text: String get() = body.decodeToString()
}

/**
 * Sends the library's HTTP requests. The default is [OkHttpTransport]; tests and apps with their own networking
 * stack can supply another.
 *
 * A transport must not follow redirects: an endpoint that redirects is answered as the redirect itself.
 */
public fun interface HttpTransport {
    public suspend fun send(request: HttpRequest, timeoutSeconds: Double): HttpResponse
}

/**
 * [HttpTransport] over OkHttp, with redirects refused, no cookies, and no caching.
 *
 * @param trust certificates to trust besides (or instead of) the system's roots.
 * @param insecureSkipTLSVerification accept any TLS server certificate. FOR LOCAL TEST PROVIDERS ONLY (a
 *   self-signed iya-sts): anybody who can intercept the connection can then impersonate the identity provider,
 *   its keys and its CAEP signals.
 */
public class OkHttpTransport(
    public val trust: TLSTrust? = null,
    public val insecureSkipTLSVerification: Boolean = false,
) : HttpTransport {
    private val base: OkHttpClient by lazy {
        val builder = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .cache(null)
            .retryOnConnectionFailure(false)
        when {
            insecureSkipTLSVerification -> {
                val trustAll = object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                }
                val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
                builder.sslSocketFactory(context.socketFactory, trustAll).hostnameVerifier { _, _ -> true }
            }
            trust != null -> {
                val manager = trust.trustManager()
                val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(manager), SecureRandom()) }
                builder.sslSocketFactory(context.socketFactory, manager)
            }
        }
        builder.build()
    }

    init {
        if (insecureSkipTLSVerification) {
            OIDCLog.log(OIDCLog.Level.WARNING, "TLS certificate verification is OFF (InsecureSkipTLSVerification). Use this only with a local test identity provider.")
        }
    }

    override suspend fun send(request: HttpRequest, timeoutSeconds: Double): HttpResponse {
        val client = base.newBuilder().callTimeout((timeoutSeconds * 1000).toLong(), TimeUnit.MILLISECONDS).build()
        val contentType = request.headers["content-type"]?.toMediaTypeOrNull()
        val body = request.body?.toRequestBody(contentType)
            ?: if (request.method in setOf("POST", "PUT", "PATCH")) ByteArray(0).toRequestBody(contentType) else null
        val builder = Request.Builder().url(request.url.toString()).method(request.method, body)
        for ((name, value) in request.headers) builder.header(name, value)
        val call = client.newCall(builder.build())
        val response = suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) = continuation.resumeWithException(e)
                override fun onResponse(call: Call, response: Response) = continuation.resume(response)
            })
        }
        return withContext(Dispatchers.IO) {
            response.use { r ->
                val headers = LinkedHashMap<String, String>()
                for (name in r.headers.names()) headers[name.lowercase()] = r.headers.values(name).joinToString(", ")
                HttpResponse(request.url, r.code, headers, r.body.bytes())
            }
        }
    }
}

/** What every request the library makes shares: the transport and the timeout. */
internal class HttpClient(val transport: HttpTransport, val timeoutSeconds: Double) {
    suspend fun send(request: HttpRequest): HttpResponse = try {
        transport.send(request, timeoutSeconds)
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        throw OIDCError(OIDCError.Kind.GENERAL, "HTTP request to ${request.url} failed: ${e.message ?: e}", code = "network_error", cause = e)
    }

    suspend fun get(url: URI, headers: Map<String, String> = mapOf("accept" to "application/json")): HttpResponse =
        send(HttpRequest(url, "GET", headers))
}

/** Reads a JSON body, turning OAuth error bodies and non-2xx responses into errors. */
internal fun readJSON(res: HttpResponse, errorKind: OIDCError.Kind = OIDCError.Kind.GENERAL): JsonElement? {
    val text = res.text
    var body: JsonElement? = null
    if (res.body.isNotEmpty()) {
        body = try { parseJson(text) } catch (e: Exception) { null }
        if (body == null && res.isOK) {
            throw OIDCError(errorKind, "Expected JSON from ${res.url}, got: ${text.take(200)}", status = res.status)
        }
    }
    if (!res.isOK) {
        val error = body["error"].stringValue
        if (error != null) {
            throw OIDCError.oauth(error, body["error_description"].stringValue, body["error_uri"].stringValue, res.status, body)
        }
        throw OIDCError(errorKind, "HTTP ${res.status} from ${res.url}${if (text.isEmpty()) "" else ": ${text.take(200)}"}",
            code = "http_error", status = res.status, response = body ?: if (text.isEmpty()) null else JsonPrimitive(text))
    }
    return body
}

/** Reads a JSON body that must be an object. */
internal fun readJSONObject(res: HttpResponse, errorKind: OIDCError.Kind = OIDCError.Kind.GENERAL): JsonObject =
    readJSON(res, errorKind) as? JsonObject ?: throw OIDCError(errorKind, "Expected a JSON object from ${res.url}", status = res.status)

// MARK: - Form and query parameters

/**
 * An ordered list of name/value pairs, encoded as `application/x-www-form-urlencoded`. Names may repeat (`resource`).
 */
public class FormParameters(pairs: List<Pair<String, String>> = emptyList()) : Iterable<Pair<String, String>> {
    private val items = pairs.toMutableList()

    public val pairs: List<Pair<String, String>> get() = items.toList()

    public fun get(name: String): String? = items.firstOrNull { it.first == name }?.second
    public fun getAll(name: String): List<String> = items.filter { it.first == name }.map { it.second }
    public fun has(name: String): Boolean = items.any { it.first == name }
    public val names: List<String> get() = items.map { it.first }.distinct()

    /** Replaces every value of [name] with this one (or removes them, for null). */
    public fun set(name: String, value: String?) {
        if (value == null) {
            items.removeAll { it.first == name }
            return
        }
        val i = items.indexOfFirst { it.first == name }
        if (i < 0) {
            items.add(name to value)
        } else {
            items[i] = name to value
            val kept = items.filterIndexed { index, p -> index == i || p.first != name }
            items.clear()
            items.addAll(kept)
        }
    }

    public fun append(name: String, value: String) {
        items.add(name to value)
    }

    public val encoded: String get() = items.joinToString("&") { "${escape(it.first)}=${escape(it.second)}" }

    override fun iterator(): Iterator<Pair<String, String>> = items.toList().iterator()

    override fun equals(other: Any?): Boolean = other is FormParameters && other.items == items
    override fun hashCode(): Int = items.hashCode()

    public companion object {
        /** Parses `a=1&b=2` (a query string or form body). `+` is a space. */
        public fun parse(string: String): FormParameters {
            val s = if (string.startsWith("?") || string.startsWith("#")) string.substring(1) else string
            val out = FormParameters()
            for (part in s.split("&")) {
                if (part.isEmpty()) continue
                val eq = part.indexOf('=')
                val name = if (eq < 0) part else part.substring(0, eq)
                val value = if (eq < 0) "" else part.substring(eq + 1)
                out.append(decode(name), decode(value))
            }
            return out
        }

        private fun decode(s: String): String = try { URLDecoder.decode(s, "UTF-8") } catch (e: Exception) { s }

        // URLEncoder leaves `-._*` and alphanumerics and turns a space into `+`, as forms are encoded.
        internal fun escape(s: String): String = URLEncoder.encode(s, "UTF-8")
    }
}

/** This URL with [params] added to its query (existing parameters are kept). */
internal fun URI.appendingQuery(params: FormParameters): URI {
    if (params.pairs.isEmpty()) return this
    val existing = rawQuery?.let { if (it.isEmpty()) "" else "$it&" } ?: ""
    val s = toString()
    val withoutFragment = s.substringBefore('#')
    val fragment = rawFragment?.let { "#$it" } ?: ""
    val base = withoutFragment.substringBefore('?')
    return URI("$base?$existing${params.encoded}$fragment")
}

internal fun headersOf(map: Map<String, String>): Headers = Headers.Builder().apply { map.forEach { (k, v) -> add(k, v) } }.build()
