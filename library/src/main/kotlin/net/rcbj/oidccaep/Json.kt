// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

// Claims, metadata and event payloads are open-ended, so the library keeps them as kotlinx.serialization
// `JsonElement`s and offers typed accessors for the members it reads.

internal val compactJson = Json { prettyPrint = false }
internal val prettyJson = Json { prettyPrint = true }

/** The string, when this is a JSON string. */
public val JsonElement?.stringValue: String? get() = (this as? JsonPrimitive)?.takeIf { it.isString }?.content
/** The boolean, when this is a JSON boolean. */
public val JsonElement?.boolValue: Boolean? get() = (this as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull
/** The number, when this is a JSON number. */
public val JsonElement?.doubleValue: Double? get() =
    (this as? JsonPrimitive)?.takeIf { !it.isString && it !is JsonNull && it.booleanOrNull == null }?.content?.toDoubleOrNull()
/** The number, when it is a whole number. */
public val JsonElement?.longValue: Long? get() = doubleValue?.takeIf { it.isFinite() && Math.rint(it) == it && kotlin.math.abs(it) < 9.0e15 }?.toLong()
public val JsonElement?.arrayValue: JsonArray? get() = this as? JsonArray
public val JsonElement?.objectValue: JsonObject? get() = this as? JsonObject
public val JsonElement?.isJsonNull: Boolean get() = this is JsonNull
/** An array of strings (non-string members are skipped), or null when this is not an array. */
public val JsonElement?.stringArrayValue: List<String>? get() = arrayValue?.mapNotNull { it.stringValue }

/** The member [key], when this is an object. */
public operator fun JsonElement?.get(key: String): JsonElement? = (this as? JsonObject)?.get(key)

/** The member [key] when it is a string. */
public fun JsonObject.string(key: String): String? = this[key].stringValue

/** Compact (or pretty-printed) JSON text. */
public fun JsonElement.jsonString(pretty: Boolean = false): String =
    (if (pretty) prettyJson else compactJson).encodeToString(JsonElement.serializer(), this)

/** Parses a JSON document. */
public fun parseJson(text: String): JsonElement = compactJson.parseToJsonElement(text)
public fun parseJson(data: ByteArray): JsonElement = parseJson(data.decodeToString())

/** Parses a JSON document that must be an object. */
public fun parseJsonObject(data: ByteArray): JsonObject =
    (try { parseJson(data) } catch (e: Exception) { throw OIDCError.validation("Expected a JSON object") }) as? JsonObject
        ?: throw OIDCError.validation("Expected a JSON object")

internal fun JsonElement.jsonBytes(): ByteArray = jsonString().encodeToByteArray()

/** JSON from Kotlin values: String, Number, Boolean, null, List, Map, and JsonElement. */
public fun jsonOf(value: Any?): JsonElement = when (value) {
    null -> JsonNull
    is JsonElement -> value
    is String -> JsonPrimitive(value)
    is Boolean -> JsonPrimitive(value)
    is Int -> JsonPrimitive(value)
    is Long -> JsonPrimitive(value)
    is Double -> if (value.isFinite() && Math.rint(value) == value && kotlin.math.abs(value) < 9.0e15) JsonPrimitive(value.toLong()) else JsonPrimitive(value)
    is Number -> JsonPrimitive(value)
    is List<*> -> JsonArray(value.map { jsonOf(it) })
    is Array<*> -> JsonArray(value.map { jsonOf(it) })
    is Map<*, *> -> JsonObject(value.entries.associate { (k, v) -> k.toString() to jsonOf(v) })
    else -> throw IllegalArgumentException("Not a JSON value: ${value::class}")
}

/** A JSON object from pairs; null values are left out. */
public fun jsonObjectOf(vararg pairs: Pair<String, Any?>): JsonObject =
    JsonObject(pairs.filter { it.second != null }.associate { (k, v) -> k to jsonOf(v) })

/** This object with [key] set (or removed, for null). */
public fun JsonObject.with(key: String, value: Any?): JsonObject {
    val m = LinkedHashMap(this)
    if (value == null) m.remove(key) else m[key] = jsonOf(value)
    return JsonObject(m)
}

/** This object with every member of [other] set over it. */
public operator fun JsonObject.plus(other: Map<String, JsonElement>): JsonObject = JsonObject(LinkedHashMap(this).apply { putAll(other) })

public val emptyJsonObject: JsonObject = JsonObject(emptyMap())
