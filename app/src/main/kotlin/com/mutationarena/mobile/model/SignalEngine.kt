package com.mutationarena.mobile.model

import android.content.Context
import com.mutationarena.mobile.data.Action
import com.mutationarena.mobile.data.Candle
import com.mutationarena.mobile.data.Signal
import org.json.JSONObject

/**
 * Runs the two bundled, fine-tuned Gemma models — Scout (fast/aggressive) and
 * Analyst (cautious/risk-aware) — on the current candles and returns their
 * signals. Both run fully on-device; nothing leaves the phone.
 */
class SignalEngine(context: Context) {
    private val scout = GemmaModel(context, "scout.task")
    private val analyst = GemmaModel(context, "analyst.task")

    val scoutInstalled get() = scout.isInstalled
    val analystInstalled get() = analyst.isInstalled

    suspend fun signals(pair: String, candles: List<Candle>): List<Signal> = listOf(
        run("Scout", scout, pair, candles, role = "an aggressive scalper looking for fast, high-conviction entries"),
        run("Analyst", analyst, pair, candles, role = "a cautious risk manager who avoids choppy, low-edge setups"),
    )

    private suspend fun run(
        name: String,
        model: GemmaModel,
        pair: String,
        candles: List<Candle>,
        role: String,
    ): Signal {
        if (!model.isInstalled) {
            return Signal(name, Action.HOLD, 0.0, "model not installed — add ${name.lowercase()}.task", ok = false)
        }
        val raw = model.generate(buildPrompt(pair, candles, role))
            ?: return Signal(name, Action.HOLD, 0.0, "inference failed", ok = false)
        return parse(name, raw)
    }

    private fun buildPrompt(pair: String, candles: List<Candle>, role: String): String {
        val recent = candles.takeLast(32)
        val closes = recent.joinToString(",") { "%.2f".format(it.close) }
        val last = recent.lastOrNull()?.close ?: 0.0
        return """
            You are $role trading $pair. You output ONLY a JSON object.
            Last price: ${"%.2f".format(last)}.
            Recent closes (oldest→newest): $closes
            Decide the next move. Respond with exactly:
            {"action":"BUY|SELL|HOLD","confidence":0.0-1.0,"reason":"short why"}
        """.trimIndent()
    }

    private fun parse(model: String, raw: String): Signal {
        return try {
            val json = raw.substringAfter('{', "").let { "{$it" }.substringBeforeLast('}') + "}"
            val o = JSONObject(json)
            val action = when (o.optString("action", "HOLD").uppercase()) {
                "BUY" -> Action.BUY
                "SELL" -> Action.SELL
                else -> Action.HOLD
            }
            Signal(
                model = model,
                action = action,
                confidence = o.optDouble("confidence", 0.5).coerceIn(0.0, 1.0),
                reason = o.optString("reason", "").take(160).ifBlank { "—" },
            )
        } catch (_: Exception) {
            Signal(model, Action.HOLD, 0.0, "could not parse model output", ok = false)
        }
    }

    fun close() {
        scout.close(); analyst.close()
    }
}
