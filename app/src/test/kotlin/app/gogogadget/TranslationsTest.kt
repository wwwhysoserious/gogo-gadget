package app.gogogadget

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class TranslationsTest {
    private val locales = listOf("values-pt", "values-pt-rPT", "values-es")
    private val placeholder = Regex("%(?:\\d+\\$)?[-#+ 0,(]*\\d*(?:\\.\\d+)?[a-zA-Z%]")

    private fun resDir(): File =
        listOf("src/main/res", "app/src/main/res").map(::File).firstOrNull { it.isDirectory }
            ?: error("res directory not found from ${File(".").absoluteFile}")

    // Maps "name" or "name#quantity" to the raw text of each string and plural item.
    private fun load(dir: String): Map<String, String> {
        val file = File(resDir(), "$dir/strings.xml")
        assertTrue("missing $file", file.isFile)
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val out = LinkedHashMap<String, String>()
        val nodes = doc.documentElement.childNodes
        for (i in 0 until nodes.length) {
            val node = nodes.item(i) as? Element ?: continue
            val name = node.getAttribute("name")
            when (node.tagName) {
                "string" -> out[name] = node.textContent
                "plurals" -> {
                    val items = node.getElementsByTagName("item")
                    for (j in 0 until items.length) {
                        val item = items.item(j) as Element
                        out["$name#${item.getAttribute("quantity")}"] = item.textContent
                    }
                }
            }
        }
        return out
    }

    private fun placeholders(text: String): List<String> =
        placeholder.findAll(text).map { it.value }.sorted().toList()

    // Plural items are compared per plural name, since translations need other quantities.
    private fun names(map: Map<String, String>): Set<String> = map.keys.map { it.substringBefore('#') }.toSet()

    @Test fun everyEnglishKeyIsTranslated() {
        val english = load("values")
        for (dir in locales) {
            val missing = names(english) - names(load(dir))
            assertTrue("$dir is missing $missing", missing.isEmpty())
        }
    }

    @Test fun noKeyExistsOnlyInATranslation() {
        val english = names(load("values"))
        for (dir in locales) {
            val extra = names(load(dir)) - english
            assertTrue("$dir has keys not in English: $extra", extra.isEmpty())
        }
    }

    @Test fun placeholdersMatchEnglish() {
        val english = load("values")
        for (dir in locales) {
            val translated = load(dir)
            for ((key, text) in english) {
                val name = key.substringBefore('#')
                val candidates = translated.filterKeys { it.substringBefore('#') == name }.values
                assertTrue("$dir lacks $name", candidates.isNotEmpty())
                for (candidate in candidates) {
                    assertEquals("$dir / $key", placeholders(text), placeholders(candidate))
                }
            }
        }
    }

    @Test fun pluralsHaveOneManyAndOther() {
        for (dir in locales) {
            val quantities = load(dir).keys.filter { it.startsWith("shield_upload_body#") }.map { it.substringAfter('#') }.toSet()
            assertEquals(dir, setOf("one", "many", "other"), quantities)
        }
    }

    @Test fun apostrophesAreEscapedInEveryFile() {
        for (dir in listOf("values") + locales) {
            val text = File(resDir(), "$dir/strings.xml").readText()
            val bad = Regex("(?<!\\\\)'").findAll(text).count()
            assertEquals("$dir has unescaped apostrophes", 0, bad)
        }
    }

    @Test fun deleteModeStringsAreFilledInEveryLanguage() {
        val keys = listOf(
            "delete_apk_off", "delete_apk_on", "delete_apk_auto",
            "backup_before_update", "virustotal_key_delete", "virustotal_key_delete_title", "virustotal_key_delete_body",
        )
        for (dir in listOf("values") + locales) {
            val strings = load(dir)
            for (key in keys) assertTrue("$dir / $key is empty", strings[key]?.isNotBlank() == true)
        }
    }

    @Test fun deleteModeLabelsUseTheOwnersWording() {
        val expected = mapOf(
            "values" to listOf("Off", "On", "Automatic"),
            "values-pt-rPT" to listOf("Desligado", "Ligado", "Autom\u00e1tico"),
            "values-es" to listOf("Desactivado", "Activado", "Autom\u00e1tico"),
            "values-fr" to listOf("D\u00e9sactiv\u00e9", "Activ\u00e9", "Automatique"),
        )
        for ((dir, labels) in expected) {
            val strings = load(dir)
            assertEquals(dir, labels, listOf("delete_apk_off", "delete_apk_on", "delete_apk_auto").map { strings.getValue(it) })
        }
    }

    @Test fun backupBeforeUpdateIsRenamed() {
        assertEquals("Backup before update", load("values")["backup_before_update"])
        assertEquals("Backup antes de atualizar", load("values-pt-rPT")["backup_before_update"])
        assertEquals("Copia de seguridad antes de actualizar", load("values-es")["backup_before_update"])
        assertEquals("Sauvegarde avant mise \u00e0 jour", load("values-fr")["backup_before_update"])
    }

    @Test fun addDeviceRowSaysAddOrRemove() {
        assertEquals("Add / remove device", load("values")["add_device"])
        assertEquals("Adicionar / remover dispositivo", load("values-pt-rPT")["add_device"])
        assertEquals("A\u00f1adir / quitar dispositivo", load("values-es")["add_device"])
        assertEquals("Ajouter / supprimer un appareil", load("values-fr")["add_device"])
    }

    @Test fun androidSystemTermsMatchWhatThePhoneShows() {
        val pair = mapOf(
            "values-pt-rPT" to "Emparelhar dispositivo com c\u00f3digo de emparelhamento",
            "values-es" to "Emparejar dispositivo con c\u00f3digo de sincronizaci\u00f3n",
            "values-fr" to "Associer l'appareil avec un code d'association",
        )
        val build = mapOf(
            "values-pt-rPT" to "N\u00famero de compila\u00e7\u00e3o",
            "values-es" to "N\u00famero de compilaci\u00f3n",
            "values-fr" to "Num\u00e9ro de build",
        )
        val wireless = mapOf(
            "values-pt-rPT" to "Depura\u00e7\u00e3o sem fios",
            "values-es" to "Depuraci\u00f3n inal\u00e1mbrica",
            "values-fr" to "D\u00e9bogage sans fil",
        )
        for (dir in locales) {
            val strings = load(dir)
            assertTrue("$dir pairing", strings.getValue("pairing_instruction").replace("\\'", "'").contains(pair.getValue(dir)))
            assertTrue("$dir build number", strings.getValue("connect_step_2").contains(build.getValue(dir)))
            assertEquals(dir, wireless.getValue(dir), strings.getValue("wireless_debugging"))
        }
    }

    @Test fun portugueseIsEuropeanPortuguese() {
        val brazilian = Regex(
            "\\b(tela|arquivos?|celular(es)?|baixar|salvar|voc\u00ea|aplicativos?|deletar|configura\u00e7\u00f5es|usu\u00e1rios?)\\b",
            RegexOption.IGNORE_CASE,
        )
        for ((key, text) in load("values-pt-rPT")) {
            assertTrue("pt-PT $key uses a Brazilian form: $text", !brazilian.containsMatchIn(text))
        }
    }

    @Test fun frenchPunctuationUsesNonBreakingSpaces() {
        for ((key, text) in load("values-fr")) {
            assertTrue("fr $key has a breaking space before : ; ? ! or a closing guillemet: $text", !Regex(" [:;?!\u00bb]").containsMatchIn(text))
            assertTrue("fr $key has a breaking space after an opening guillemet: $text", !text.contains("\u00ab "))
        }
    }

    @Test fun howItWorksAndSecurityApiStringsAreFilledAndKeysAreNeverRequired() {
        val keys = (1..5).flatMap { listOf("how_s${it}_head", "how_s${it}_body") } +
            (1..7).flatMap { listOf("how_t${it}_head", "how_t${it}_body") } +
            listOf(
                "how_it_works", "how_title_technical", "security_apis", "security_apis_intro", "api_vt_limit", "api_md_limit",
                "api_step_1", "api_step_2", "api_step_3", "api_create_account", "welcome_body", "welcome_skip", "welcome_skip_note",
                "protection_limited", "protection_maximum", "shield_info_description", "shield_info_report", "shield_warn_vt_key_missing",
            )
        for (dir in listOf("values") + locales) {
            val strings = load(dir)
            for (key in keys) assertTrue("$dir / $key is empty", strings[key]?.isNotBlank() == true)
            assertTrue("$dir still has the tagline", "tagline_title" !in strings && "tagline_points" !in strings)
            assertTrue("$dir calls the key required", !Regex("(?i)required|obrigat|requerid|necesari|obligatoire").containsMatchIn(strings.getValue("shield_warn_vt_key_missing")))
        }
    }
}
