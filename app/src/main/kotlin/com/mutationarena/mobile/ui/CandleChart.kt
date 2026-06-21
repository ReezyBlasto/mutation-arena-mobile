package com.mutationarena.mobile.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.unit.dp
import androidx.compose.material3.Text
import androidx.compose.ui.text.style.TextAlign
import com.mutationarena.mobile.data.Candle
import com.mutationarena.mobile.ui.theme.Buy
import com.mutationarena.mobile.ui.theme.Fg3
import com.mutationarena.mobile.ui.theme.Sell

/** A lightweight candlestick chart drawn on a Compose Canvas. Green up, red down. */
@Composable
fun CandleChart(candles: List<Candle>, modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxWidth().height(260.dp), contentAlignment = Alignment.Center) {
        if (candles.isEmpty()) {
            Text(
                "no candles — check connection or pick a market",
                color = Fg3,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(24.dp),
            )
            return@Box
        }

        Canvas(modifier = Modifier.fillMaxSize().padding(8.dp)) {
            val view = candles.takeLast(80)
            val hi = view.maxOf { it.high }
            val lo = view.minOf { it.low }
            val span = (hi - lo).takeIf { it > 0.0 } ?: 1.0
            val w = size.width
            val h = size.height
            val slot = w / view.size
            val bodyW = (slot * 0.62f).coerceAtLeast(1f)

            fun y(price: Double): Float = (h - ((price - lo) / span * h)).toFloat()

            view.forEachIndexed { i, c ->
                val cx = i * slot + slot / 2f
                val up = c.close >= c.open
                val color = if (up) Buy else Sell
                // wick
                drawLine(
                    color = color,
                    start = Offset(cx, y(c.high)),
                    end = Offset(cx, y(c.low)),
                    strokeWidth = 1.2f,
                    cap = StrokeCap.Round,
                )
                // body
                val top = y(maxOf(c.open, c.close))
                val bot = y(minOf(c.open, c.close))
                drawRect(
                    color = color,
                    topLeft = Offset(cx - bodyW / 2f, top),
                    size = androidx.compose.ui.geometry.Size(bodyW, (bot - top).coerceAtLeast(1f)),
                )
            }
        }
    }
}
