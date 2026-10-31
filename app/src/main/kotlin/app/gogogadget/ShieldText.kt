package app.gogogadget

// Which string resource says what, for every Shield reason, finding and source status. Pure code (resource ids only), so a
// JVM test can check that every case has text in every language. English technical lines never reach a translated screen;
// they stay in the terminal log.

/** A string resource and its format arguments. */
data class TextSpec(val resId: Int, val args: List<String> = emptyList())

/** The title, the sentence that says what was found, and (when there is one) what it means for the user. */
data class ReasonText(val titleRes: Int, val whatRes: Int, val meaningRes: Int?)

/** The sentence without arguments that is shown on the main button when the reason blocks or cancels the install. */
fun shortReasonRes(reason: ShieldWarningReason): Int = when (reason) {
    ShieldWarningReason.MalwareDetected -> R.string.shield_warn_malware_short
    ShieldWarningReason.UnsignedPackage -> R.string.shield_warn_unsigned
    ShieldWarningReason.DebugOrTestCertificate -> R.string.shield_warn_debug_cert
    ShieldWarningReason.SignatureMismatch -> R.string.shield_warn_signature
    ShieldWarningReason.VersionDowngrade -> R.string.shield_warn_downgrade
    ShieldWarningReason.VirusTotalKeyMissing -> R.string.shield_warn_vt_key_missing
    ShieldWarningReason.NotKnownToVirusTotal -> R.string.shield_warn_not_known
    ShieldWarningReason.VirusTotalUnreachable -> R.string.shield_warn_vt_unreachable
    ShieldWarningReason.OnlineRateLimited -> R.string.shield_warn_online_rate_limited
    ShieldWarningReason.OnlineKeyRejected -> R.string.shield_warn_online_key_rejected
    ShieldWarningReason.StaleAnalysis -> R.string.shield_warn_old_analysis
    ShieldWarningReason.TooFewEngines -> R.string.shield_warn_few_engines
    ShieldWarningReason.EnginesFlagged -> R.string.shield_warn_engines_flagged_short
    ShieldWarningReason.PackageMismatch -> R.string.shield_warn_package_mismatch
    ShieldWarningReason.DropperDetected -> R.string.shield_warn_dropper_short
    ShieldWarningReason.AdwareDetected -> R.string.shield_warn_adware_short
    ShieldWarningReason.AbusivePermissions -> R.string.shield_warn_abusive_permissions_short
    ShieldWarningReason.RiskyPermissionCombo -> R.string.shield_warn_permission_combo
    ShieldWarningReason.SelfUpdaterPermission -> R.string.shield_warn_self_updater
    ShieldWarningReason.CompromisedKey -> R.string.shield_warn_compromised_key
    ShieldWarningReason.LegacySignatureOnly -> R.string.shield_warn_legacy_signature
    ShieldWarningReason.MalformedArchive -> R.string.shield_warn_malformed_archive
    ShieldWarningReason.InvalidNativeLibrary -> R.string.shield_warn_invalid_native
    ShieldWarningReason.SuspiciousNativeCode -> R.string.shield_warn_suspicious_native
    ShieldWarningReason.ScanIncomplete -> R.string.shield_warn_scan_incomplete
}

/**
 * The text of a reason on the caution card and in the report. [ReasonText.whatRes] takes no arguments, except
 * [ShieldWarningReason.MalwareDetected] and [ShieldWarningReason.EnginesFlagged] which take the flagging and the asked
 * engines (see [reasonWhatSpec]).
 */
fun reasonText(reason: ShieldWarningReason): ReasonText = when (reason) {
    ShieldWarningReason.MalwareDetected -> ReasonText(R.string.reason_title_malware, R.string.shield_warn_malware, null)
    ShieldWarningReason.EnginesFlagged -> ReasonText(R.string.reason_title_engines_flagged, R.string.shield_warn_engines_flagged, R.string.caution_engines_flagged_risk)
    ShieldWarningReason.DropperDetected -> ReasonText(R.string.reason_title_hidden_code, R.string.shield_warn_dropper, R.string.caution_dropper_risk)
    ShieldWarningReason.DebugOrTestCertificate -> ReasonText(R.string.reason_title_test_cert, R.string.shield_warn_debug_cert, R.string.caution_debug_cert_risk)
    ShieldWarningReason.SuspiciousNativeCode -> ReasonText(R.string.reason_title_native_code, R.string.shield_warn_suspicious_native, R.string.caution_suspicious_native_risk)
    ShieldWarningReason.InvalidNativeLibrary -> ReasonText(R.string.reason_title_native_invalid, R.string.shield_warn_invalid_native, null)
    ShieldWarningReason.RiskyPermissionCombo -> ReasonText(R.string.reason_title_permission_combo, R.string.shield_warn_permission_combo, null)
    ShieldWarningReason.ScanIncomplete -> ReasonText(R.string.reason_title_scan_incomplete, R.string.shield_warn_scan_incomplete, R.string.caution_scan_incomplete_risk)
    ShieldWarningReason.NotKnownToVirusTotal -> ReasonText(R.string.reason_title_not_known, R.string.shield_warn_not_known, R.string.caution_not_known_risk)
    ShieldWarningReason.VirusTotalUnreachable -> ReasonText(R.string.reason_title_online_unavailable, R.string.shield_warn_vt_unreachable, null)
    ShieldWarningReason.OnlineRateLimited -> ReasonText(R.string.reason_title_online_quota, R.string.shield_warn_online_rate_limited, null)
    ShieldWarningReason.OnlineKeyRejected -> ReasonText(R.string.reason_title_online_key, R.string.shield_warn_online_key_rejected, null)
    ShieldWarningReason.TooFewEngines -> ReasonText(R.string.reason_title_few_engines, R.string.shield_warn_few_engines, null)
    ShieldWarningReason.StaleAnalysis -> ReasonText(R.string.reason_title_old_analysis, R.string.shield_warn_old_analysis, null)
    ShieldWarningReason.VirusTotalKeyMissing -> ReasonText(R.string.reason_title_not_checked_online, R.string.shield_warn_vt_key_missing, R.string.caution_vt_key_missing_risk)
    ShieldWarningReason.SelfUpdaterPermission -> ReasonText(R.string.reason_title_self_updater, R.string.shield_warn_self_updater, R.string.caution_self_updater_risk)
    ShieldWarningReason.UnsignedPackage -> ReasonText(R.string.reason_title_unsigned, R.string.shield_warn_unsigned, null)
    ShieldWarningReason.SignatureMismatch -> ReasonText(R.string.reason_title_signature, R.string.shield_warn_signature, null)
    ShieldWarningReason.VersionDowngrade -> ReasonText(R.string.reason_title_downgrade, R.string.shield_warn_downgrade, null)
    ShieldWarningReason.PackageMismatch -> ReasonText(R.string.reason_title_package_mismatch, R.string.shield_warn_package_mismatch, null)
    ShieldWarningReason.AdwareDetected -> ReasonText(R.string.reason_title_adware, R.string.shield_warn_adware, null)
    ShieldWarningReason.AbusivePermissions -> ReasonText(R.string.reason_title_abusive, R.string.shield_warn_abusive_permissions, null)
    ShieldWarningReason.CompromisedKey -> ReasonText(R.string.reason_title_compromised_key, R.string.shield_warn_compromised_key, null)
    ShieldWarningReason.LegacySignatureOnly -> ReasonText(R.string.reason_title_legacy_signature, R.string.shield_warn_legacy_signature, null)
    ShieldWarningReason.MalformedArchive -> ReasonText(R.string.reason_title_malformed, R.string.shield_warn_malformed_archive, null)
}

/**
 * The "what was found" sentence of [reason] with its arguments: the engine counts for [ShieldWarningReason.MalwareDetected] and
 * [ShieldWarningReason.EnginesFlagged] come from [verdict]'s report.
 */
fun reasonWhatSpec(reason: ShieldWarningReason, flagged: Int, total: Int): TextSpec {
    val text = reasonText(reason)
    return when (reason) {
        ShieldWarningReason.MalwareDetected, ShieldWarningReason.EnginesFlagged ->
            TextSpec(text.whatRes, listOf(flagged.toString(), total.coerceAtLeast(flagged).toString()))
        else -> TextSpec(text.whatRes)
    }
}

/** The sentence for one deep-scan finding, in the user's language; [StaticAnalysisIssue.apk] is added by the screen. */
fun issueTextSpec(issue: StaticAnalysisIssue): TextSpec {
    val p1 = issue.param.orEmpty()
    val p2 = issue.param2.orEmpty()
    return when (issue.code) {
        IssueCode.HiddenDex -> TextSpec(R.string.issue_hidden_dex, listOf(p1))
        IssueCode.HiddenApk -> TextSpec(R.string.issue_hidden_apk, listOf(p1))
        IssueCode.HiddenNative -> TextSpec(R.string.issue_hidden_native, listOf(p1))
        IssueCode.HiddenInArchive -> TextSpec(R.string.issue_hidden_archive, listOf(p1, p2))
        IssueCode.EncryptedBlob -> TextSpec(R.string.issue_encrypted_blob, listOf(p1))
        IssueCode.LoaderWithPath -> TextSpec(R.string.issue_loader_path, listOf(p1))
        IssueCode.AdwareSdk -> TextSpec(R.string.issue_adware_sdk, listOf(p1))
        IssueCode.AbusiveCombo -> TextSpec(R.string.issue_abusive_combo)
        IssueCode.InstallOverlay -> TextSpec(R.string.issue_install_overlay)
        IssueCode.InstallSms -> TextSpec(R.string.issue_install_sms, listOf(p1))
        IssueCode.SmsOverlay -> TextSpec(R.string.issue_sms_overlay, listOf(p1))
        IssueCode.SelfUpdater -> TextSpec(R.string.issue_self_updater, listOf(p1))
        IssueCode.NativeNotElf -> TextSpec(R.string.issue_native_not_elf, listOf(p1))
        IssueCode.NativeBadHeader -> TextSpec(R.string.issue_native_bad_header, listOf(p1))
        IssueCode.NativeAbiMismatch -> TextSpec(R.string.issue_native_abi, listOf(p1, p2))
        IssueCode.NativePacker -> TextSpec(R.string.issue_native_packer, listOf(p1))
        IssueCode.NativeMarker -> TextSpec(R.string.issue_native_marker, listOf(p1, p2))
        IssueCode.DexUnreadable -> TextSpec(R.string.issue_dex_unreadable, listOf(p1))
        IssueCode.DexTooBig -> TextSpec(R.string.issue_dex_too_big, listOf(p1))
        IssueCode.DexStringsCut -> TextSpec(R.string.issue_dex_strings_cut, listOf(p1))
        IssueCode.NestedTooBig -> TextSpec(R.string.issue_nested_too_big, listOf(p1))
        IssueCode.NestedUnreadable -> TextSpec(R.string.issue_nested_unreadable, listOf(p1))
        IssueCode.ArchiveUnreadable -> TextSpec(R.string.issue_archive_unreadable, listOf(p1))
        IssueCode.ApkMissing -> TextSpec(R.string.issue_apk_missing, listOf(p1))
        IssueCode.InstalledQueryFailed -> TextSpec(R.string.issue_installed_query_failed)
        IssueCode.Generic -> TextSpec(R.string.issue_generic)
    }
}

/** The line that says what one source answered about one file; [SourceReport.total] and [SourceReport.flagged] fill the counts. */
fun sourceStatusSpec(report: SourceReport): TextSpec {
    val name = report.source.displayName
    return when (report.status) {
        SourceStatus.Answered -> TextSpec(R.string.report_source_answered, listOf(name, report.flagged.toString(), report.total.toString()))
        SourceStatus.UnknownHash -> TextSpec(R.string.report_source_unknown, listOf(name))
        SourceStatus.Unavailable -> TextSpec(R.string.report_source_unavailable, listOf(name))
        SourceStatus.RateLimited -> TextSpec(R.string.report_source_rate_limited, listOf(name))
        SourceStatus.InvalidKey -> TextSpec(R.string.report_source_key_rejected, listOf(name))
        SourceStatus.NotQueried -> TextSpec(R.string.report_source_not_queried, listOf(name))
    }
}
