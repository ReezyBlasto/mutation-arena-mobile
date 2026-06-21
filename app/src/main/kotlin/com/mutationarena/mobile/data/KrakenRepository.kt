package com.mutationarena.mobile.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Fetches REAL OHLC candles from Kraken's public REST API. No fabricated data —
 * on failure the caller gets an empty list and shows an empty/error state.
 *
 * GET https://api.kraken.com/0/public/OHLC?pair=<pair>&interval=<minutes>
 * Response: { error:[], result:{ <PAIR>: [[time,open,high,low,close,vwap,volume,count], ...], last:... } }
 */
class KrakenRepository(
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build(),
) {
    suspend fun ohlc(pair: String, intervalMinutes: Int): List<Candle> = withContext(Dispatchers.IO) {
        val url = "https://api.kraken.com/0/public/OHLC?pair=$pair&interval=$intervalMinutes"
        val req = Request.Builder().url(url).header("User-Agent", "MutationArenaMobile/0.1").build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@withContext emptyList()
            val body = resp.body?.string() ?: return@withContext emptyList()
            parse(body)
        }
    }

    private fun parse(body: String): List<Candle> {
        return try {
            val root = JSONObject(body)
            val errors = root.optJSONArray("error")
            if (errors != null && errors.length() > 0) return emptyList()
            val result = root.optJSONObject("result") ?: return emptyList()
            // The candle array is keyed by the resolved pair name (not always the request key).
            val key = result.keys().asSequence().firstOrNull { it != "last" } ?: return emptyList()
            val arr = result.optJSONArray(key) ?: return emptyList()
            buildList {
                for (i in 0 until arr.length()) {
                    val c = arr.getJSONArray(i)
                    add(
                        Candle(
                            time = c.getLong(0),
                            open = c.getString(1).toDouble(),
                            high = c.getString(2).toDouble(),
                            low = c.getString(3).toDouble(),
                            close = c.getString(4).toDouble(),
                            volume = c.getString(6).toDouble(),
                        )
                    )
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}
