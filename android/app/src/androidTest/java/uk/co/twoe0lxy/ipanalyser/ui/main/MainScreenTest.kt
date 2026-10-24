package uk.co.twoe0lxy.ipanalyser.ui.main

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertExists
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import org.junit.Rule
import org.junit.Test

class MainScreenTest {
  @get:Rule val composeTestRule = createAndroidComposeRule<ComponentActivity>()

  @Test
  fun dashboardAndPrimaryActionAreVisible() {
    composeTestRule.setContent { MainScreen() }
    composeTestRule.onNodeWithText("Network Dashboard").assertExists()
    composeTestRule.onNodeWithText("Scan network").assertExists()
  }
}
