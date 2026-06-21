package com.mutationarena.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mutationarena.mobile.data.Action
import com.mutationarena.mobile.data.Signal
import com.mutationarena.mobile.ui.theme.Buy
import com.mutationarena.mobile.ui.theme.Fg1
import com.mutationarena.mobile.ui.theme.Fg2
import com.mutationarena.mobile.ui.theme.Fg3
import com.mutationarena.mobile.ui.theme.Line2
import com.mutationarena.mobile.ui.theme.Sell

@Composable
fun SignalPanel(signals: List<Signal>, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (signals.isEmpty()) {
            Text("Run the models for a read on this market.", color = Fg3, fontSize = 13.sp)
        }
        signals.forEach { SignalCard(it) }
    }
}

@Composable
private fun SignalCard(s: Signal) {
    val color = when (s.action) {
        Action.BUY -> Buy
        Action.SELL -> Sell
        Action.HOLD -> Fg3
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Line2, RoundedCornerShape(12.dp))
            .background(androidx.compose.ui.graphics.Color(0xFF0B0F15), RoundedCornerShape(12.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(s.model, color = Fg1, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                Text(
                    if (s.ok) s.action.name else "—",
                    color = color,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                )
                if (s.ok) {
                    Text(
                        "  ${(s.confidence * 100).toInt()}%",
                        color = Fg2,
                        fontSize = 13.sp,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
            }
        }
        Text(s.reason, color = if (s.ok) Fg2 else Sell, fontSize = 13.sp)
    }
}
