package com.mutationarena.mobile.data

import java.util.UUID

data class LogEntry(
    val id: String = UUID.randomUUID().toString(),
    val agentName: String,
    val pair: String,
    val timeframeMinutes: Int,
    val action: Action,
    val confidence: Double,
    val priceAtSignal: Double,
    val candleTimeAtSignal: Long,   // unix seconds — used to determine when to score
    val outcome: Outcome = Outcome.PENDING,
    val priceAtOutcome: Double? = null,
)

enum class Outcome { PENDING, WIN, LOSS, SKIPPED }

data class AgentStats(
    val agentName: String,
    val totalCalls: Int,
    val actionCalls: Int,           // non-HOLD calls
    val wins: Int,
    val losses: Int,
    val pending: Int,
) {
    // Excludes HOLD and PENDING from win-rate denominator — only scored moves count.
    val winRate: Double get() = if (wins + losses > 0) wins.toDouble() / (wins + losses) else 0.0
    val actionRate: Double get() = if (totalCalls > 0) actionCalls.toDouble() / totalCalls else 0.0
}
