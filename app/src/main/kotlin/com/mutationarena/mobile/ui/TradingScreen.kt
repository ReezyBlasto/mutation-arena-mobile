package com.mutationarena.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mutationarena.mobile.data.AccountabilityLogger
import com.mutationarena.mobile.data.AgentStats
import com.mutationarena.mobile.data.Candle
import com.mutationarena.mobile.data.KrakenRepository
import com.mutationarena.mobile.data.MARKETS
import com.mutationarena.mobile.data.Market
import com.mutationarena.mobile.data.Signal
import com.mutationarena.mobile.data.TIMEFRAMES
import com.mutationarena.mobile.model.SignalEngine
import com.mutationarena.mobile.ui.theme.Bg2
import com.mutationarena.mobile.ui.theme.Brand
import com.mutationarena.mobile.ui.theme.BrandSoft
import com.mutationarena.mobile.ui.theme.Buy
import com.mutationarena.mobile.ui.theme.Fg1
import com.mutationarena.mobile.ui.theme.Fg2
import com.mutationarena.mobile.ui.theme.Fg3
import com.mutationarena.mobile.ui.theme.Line2
import com.mutationarena.mobile.ui.theme.Sell
import kotlinx.coroutines.launch

@Composable
fun TradingScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val repo = remember { KrakenRepository() }
    val engine = remember { SignalEngine(context) }
    val logger = remember { AccountabilityLogger(context) }
    val scope = rememberCoroutineScope()

    var market by remember { mutableStateOf(MARKETS.first()) }
    var tf by remember { mutableStateOf(5) } // minutes — scalping default 5m
    var candles by remember { mutableStateOf<List<Candle>>(emptyList()) }
    var signals by remember { mutableStateOf<List<Signal>>(emptyList()) }
    var agentStats by remember { mutableStateOf<Map<String, AgentStats>>(emptyMap()) }
    var loading by remember { mutableStateOf(false) }
    var running by remember { mutableStateOf(false) }

    // (Re)load candles whenever the market or timeframe changes.
    // Also score any pending signals against the fresh data.
    LaunchedEffect(market.pair, tf) {
        loading = true
        candles = repo.ohlc(market.pair, tf)
        logger.evaluate(market.pair, tf, candles)
        agentStats = listOf("Scout", "Analyst").associateWith { logger.stats(it) }
        loading = false
    }

    val last = candles.lastOrNull()?.close
    val change = if (candles.size >= 2) {
        val first = candles.first().close
        if (first > 0) (candles.last().close - first) / first * 100 else 0.0
    } else 0.0

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // Header
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text("MUTATION ARENA", color = Brand, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text("on-device · 2× Gemma", color = Fg3, fontSize = 13.sp)
            }
        }

        // Market selector
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            MARKETS.forEach { m -> Chip(m.label, m.pair == market.pair) { market = m } }
        }

        // Price + 24h-ish change
        Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(last?.let { "$" + "%.2f".format(it) } ?: "—", color = Fg1, fontWeight = FontWeight.Bold, fontSize = 28.sp)
            Text(
                (if (change >= 0) "+" else "") + "%.2f".format(change) + "%",
                color = if (change >= 0) Buy else Sell,
                fontSize = 14.sp,
                modifier = Modifier.padding(bottom = 6.dp),
            )
        }

        // Timeframe row (scalping-first)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("TF", color = Fg3, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp, end = 2.dp))
            TIMEFRAMES.forEach { (m, label) -> Chip(label, m == tf, compact = true) { tf = m } }
        }

        // Chart
        CandleChart(
            candles = candles,
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Line2, RoundedCornerShape(12.dp))
                .background(Bg2, RoundedCornerShape(12.dp)),
        )
        if (loading) Text("loading candles…", color = Fg3, fontSize = 13.sp)

        // Run models
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Signals", color = Fg1, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                RunButton(running) {
                    if (!running && candles.isNotEmpty()) {
                        running = true
                        scope.launch {
                            signals = engine.signals(market.pair, candles)
                            signals.forEach { logger.log(it, market.pair, tf, candles) }
                            agentStats = listOf("Scout", "Analyst").associateWith { logger.stats(it) }
                            running = false
                        }
                    }
                }
            }
        }

        if (!engine.scoutInstalled || !engine.analystInstalled) {
            Text(
                "Models not installed. Add scout.task / analyst.task to assets/models (see README).",
                color = Fg3,
                fontSize = 13.sp,
            )
        }

        SignalPanel(signals, agentStats)
    }
}

@Composable
private fun Chip(label: String, active: Boolean, compact: Boolean = false, onClick: () -> Unit) {
    Text(
        text = label,
        color = if (active) Brand else Fg2,
        fontSize = 13.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier
            .border(1.dp, if (active) Brand else Line2, RoundedCornerShape(8.dp))
            .background(if (active) BrandSoft else androidx.compose.ui.graphics.Color.Transparent, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = if (compact) 9.dp else 12.dp, vertical = if (compact) 5.dp else 7.dp),
    )
}

@Composable
private fun RunButton(running: Boolean, onClick: () -> Unit) {
    Text(
        text = if (running) "running…" else "▶ Run models",
        color = androidx.compose.ui.graphics.Color.White,
        fontSize = 14.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier
            .background(Brand, RoundedCornerShape(9.dp))
            .clickable(enabled = !running, onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 10.dp),
    )
}
