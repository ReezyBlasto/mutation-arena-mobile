package com.mutationarena.mobile

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.mutationarena.mobile.ui.TradingScreen
import com.mutationarena.mobile.ui.theme.Bg0
import com.mutationarena.mobile.ui.theme.MutationArenaTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            MutationArenaTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Bg0) {
                    TradingScreen(modifier = Modifier.systemBarsPadding())
                }
            }
        }
    }
}
