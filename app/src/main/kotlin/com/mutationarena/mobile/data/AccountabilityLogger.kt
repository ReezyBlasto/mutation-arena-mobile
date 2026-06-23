package com.mutationarena.mobile.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

// Score a signal after this many candles have closed since it was issued.
private const val OUTCOME_CANDLES = 5

class AccountabilityLogger(context: Context) {
    private val file = File(context.filesDir, "signal_log.json")
    private val entries = mutableListOf<LogEntry>()

    init { load() }

    /** Record a new signal. No-ops on failed/uninstalled model signals. */
    fun log(signal: Signal, pair: String, timeframeMinutes: Int, candles: List<Candle>) {
        if (!signal.ok || candles.isEmpty()) return
        entries.add(
            LogEntry(
                agentName = signal.model,
                pair = pair,
                timeframeMinutes = timeframeMinutes,
                action = signal.action,
                confidence = signal.confidence,
                priceAtSignal = candles.last().close,
                candleTimeAtSignal = candles.last().time,
            )
        )
        save()
    }

    /**
     * Score PENDING entries for this pair/timeframe using fresh candle data.
     * An entry is ready to score once OUTCOME_CANDLES intervals have elapsed
     * since the candle that triggered the signal.
     */
    fun evaluate(pair: String, timeframeMinutes: Int, candles: List<Candle>) {
        if (candles.isEmpty()) return
        val currentCandleTime = candles.last().time
        val currentPrice = candles.last().close
        val intervalSeconds = timeframeMinutes * 60L
        var changed = false

        val updated = entries.map { entry ->
            if (entry.outcome != Outcome.PENDING
                || entry.pair != pair
                || entry.timeframeMinutes != timeframeMinutes
            ) return@map entry

            val elapsed = currentCandleTime - entry.candleTimeAtSignal
            if (elapsed < intervalSeconds * OUTCOME_CANDLES) return@map entry

            changed = true
            if (entry.action == Action.HOLD) {
                return@map entry.copy(outcome = Outcome.SKIPPED)
            }
            val outcome = when (entry.action) {
                Action.BUY  -> if (currentPrice > entry.priceAtSignal) Outcome.WIN else Outcome.LOSS
                Action.SELL -> if (currentPrice < entry.priceAtSignal) Outcome.WIN else Outcome.LOSS
                Action.HOLD -> Outcome.SKIPPED
            }
            entry.copy(outcome = outcome, priceAtOutcome = currentPrice)
        }

        if (changed) {
            entries.clear()
            entries.addAll(updated)
            save()
        }
    }

    fun stats(agentName: String): AgentStats {
        val mine = entries.filter { it.agentName == agentName }
        return AgentStats(
            agentName = agentName,
            totalCalls = mine.size,
            actionCalls = mine.count { it.action != Action.HOLD },
            wins = mine.count { it.outcome == Outcome.WIN },
            losses = mine.count { it.outcome == Outcome.LOSS },
            pending = mine.count { it.outcome == Outcome.PENDING },
        )
    }

    fun allEntries(): List<LogEntry> = entries.toList()

    private fun save() {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(JSONObject().apply {
                put("id", e.id)
                put("agentName", e.agentName)
                put("pair", e.pair)
                put("timeframeMinutes", e.timeframeMinutes)
                put("action", e.action.name)
                put("confidence", e.confidence)
                put("priceAtSignal", e.priceAtSignal)
                put("candleTimeAtSignal", e.candleTimeAtSignal)
                put("outcome", e.outcome.name)
                e.priceAtOutcome?.let { put("priceAtOutcome", it) }
            })
        }
        runCatching { file.writeText(arr.toString()) }
    }

    private fun load() {
        if (!file.exists()) return
        runCatching {
            val arr = JSONArray(file.readText())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                entries.add(
                    LogEntry(
                        id = o.optString("id", UUID.randomUUID().toString()),
                        agentName = o.getString("agentName"),
                        pair = o.getString("pair"),
                        timeframeMinutes = o.getInt("timeframeMinutes"),
                        action = Action.valueOf(o.getString("action")),
                        confidence = o.getDouble("confidence"),
                        priceAtSignal = o.getDouble("priceAtSignal"),
                        candleTimeAtSignal = o.getLong("candleTimeAtSignal"),
                        outcome = Outcome.valueOf(o.optString("outcome", "PENDING")),
                        priceAtOutcome = if (o.has("priceAtOutcome")) o.getDouble("priceAtOutcome") else null,
                    )
                )
            }
        }
        // Corrupted log is silently discarded — entries stays empty.
    }
}
