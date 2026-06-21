package com.mutationarena.mobile.data

/** One OHLC candle. time is unix seconds. */
data class Candle(
    val time: Long,
    val open: Double,
    val high: Double,
    val low: Double,
    val close: Double,
    val volume: Double,
)

enum class Action { BUY, SELL, HOLD }

/** A model's call on the current market. */
data class Signal(
    val model: String,        // "Scout" | "Analyst"
    val action: Action,
    val confidence: Double,   // 0..1
    val reason: String,
    val ok: Boolean = true,   // false = model not installed / failed
)

/** A tradable market + the scalping timeframes offered. */
data class Market(val pair: String, val label: String)

val MARKETS = listOf(
    Market("XBTUSD", "BTC/USD"),
    Market("ETHUSD", "ETH/USD"),
    Market("SOLUSD", "SOL/USD"),
)

// Scalping-first timeframes, in MINUTES (Kraken OHLC interval values).
val TIMEFRAMES = listOf(1 to "1m", 5 to "5m", 15 to "15m", 30 to "30m", 60 to "1h", 240 to "4h")
