package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Test

class ThemeSettingTest {
    @Test fun systemFollowsDarkFlag() {
        assertEquals(DarkPalette, resolvePalette(ThemeSetting.System, isSystemDark = true))
        assertEquals(LightPalette, resolvePalette(ThemeSetting.System, isSystemDark = false))
    }

    @Test fun explicitSettingsIgnoreSystem() {
        for (dark in listOf(true, false)) {
            assertEquals(LightPalette, resolvePalette(ThemeSetting.Light, dark))
            assertEquals(BluePalette, resolvePalette(ThemeSetting.Blue, dark))
            assertEquals(DarkPalette, resolvePalette(ThemeSetting.Dark, dark))
        }
    }

    @Test fun bannerMatchesTheme() {
        assertEquals(Banner.A, LightPalette.banner)
        assertEquals(Banner.B, BluePalette.banner)
        assertEquals(Banner.C, DarkPalette.banner)
    }

    @Test fun storedThemeFallsBackToSystem() {
        assertEquals(ThemeSetting.System, themeSettingFromName(null))
        assertEquals(ThemeSetting.System, themeSettingFromName("Nope"))
        assertEquals(ThemeSetting.System, themeSettingFromName(""))
        for (setting in ThemeSetting.entries) assertEquals(setting, themeSettingFromName(setting.name))
    }
}
