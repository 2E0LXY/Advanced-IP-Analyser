package uk.co.twoe0lxy.ipanalyser.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
  primary = Blue500,
  secondary = Green400,
  tertiary = Orange400,
  background = Navy950,
  surface = Navy900,
  surfaceVariant = Navy800,
  onPrimary = TextPrimary,
  onBackground = TextPrimary,
  onSurface = TextPrimary,
  onSurfaceVariant = TextSecondary,
)

@Composable
fun AdvancedIPAnalyserTheme(
  content: @Composable () -> Unit,
) {
  MaterialTheme(colorScheme = DarkColorScheme, typography = Typography, content = content)
}
