package com.mutationarena.mobile.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.sp

// Kraken CLI design-system palette. Purple is reserved for brand/active only;
// green = buy/up, red = sell/down.
val Brand = Color(0xFF6B4FE8)
val BrandSoft = Color(0xFF1E1840)
val Buy = Color(0xFF00D38A)
val Sell = Color(0xFFFF4D5E)
val Bg0 = Color(0xFF07090C)
val Bg1 = Color(0xFF0B0F15)
val Bg2 = Color(0xFF11171F)
val Bg3 = Color(0xFF182030)
val Line2 = Color(0xFF283449)
val Fg1 = Color(0xFFE8ECF2)
val Fg2 = Color(0xFFA6B0C0)
val Fg3 = Color(0xFF6A7689)

private val ArenaColors = darkColorScheme(
    primary = Brand,
    onPrimary = Color.White,
    secondary = Buy,
    background = Bg0,
    onBackground = Fg1,
    surface = Bg2,
    onSurface = Fg1,
    surfaceVariant = Bg3,
    outline = Line2,
    error = Sell,
)

// Min 13sp everywhere; tabular feel via the default mono where used.
private val ArenaType = Typography(
    titleLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.SemiBold, fontSize = 20.sp),
    titleMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.SemiBold, fontSize = 16.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp),
    bodySmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 13.sp),
    labelSmall = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
)

@Composable
fun MutationArenaTheme(content: @Composable () -> Unit) {
    @Suppress("UNUSED_EXPRESSION") isSystemInDarkTheme() // always dark; this is a terminal theme
    MaterialTheme(colorScheme = ArenaColors, typography = ArenaType, content = content)
}
