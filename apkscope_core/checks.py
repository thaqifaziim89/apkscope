"""Security checks run against a parsed Manifest.

Each check is a small function that takes a Manifest and returns a list of
Finding objects. New checks only need to be added to the CHECKS list.
"""

from dataclasses import dataclass, asdict

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
SEVERITY_WEIGHT = {"High": 20, "Medium": 8, "Low": 3, "Info": 0}

# Android "dangerous" runtime permissions grouped by what they expose.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "SMS",
    "android.permission.SEND_SMS": "SMS",
    "android.permission.RECEIVE_SMS": "SMS",
    "android.permission.RECEIVE_MMS": "SMS",
    "android.permission.READ_CALL_LOG": "Call log",
    "android.permission.WRITE_CALL_LOG": "Call log",
    "android.permission.PROCESS_OUTGOING_CALLS": "Call log",
    "android.permission.CALL_PHONE": "Phone",
    "android.permission.READ_PHONE_STATE": "Phone",
    "android.permission.READ_PHONE_NUMBERS": "Phone",
    "android.permission.RECORD_AUDIO": "Microphone",
    "android.permission.CAMERA": "Camera",
    "android.permission.ACCESS_FINE_LOCATION": "Location",
    "android.permission.ACCESS_COARSE_LOCATION": "Location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Location",
    "android.permission.READ_CONTACTS": "Contacts",
    "android.permission.WRITE_CONTACTS": "Contacts",
    "android.permission.GET_ACCOUNTS": "Contacts",
    "android.permission.READ_CALENDAR": "Calendar",
    "android.permission.WRITE_CALENDAR": "Calendar",
    "android.permission.BODY_SENSORS": "Sensors",
    "android.permission.READ_EXTERNAL_STORAGE": "Storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Storage",
    "android.permission.READ_MEDIA_IMAGES": "Storage",
    "android.permission.READ_MEDIA_VIDEO": "Storage",
    "android.permission.READ_MEDIA_AUDIO": "Storage",
}
# Categories that are especially sensitive (spyware / fraud indicators).
SENSITIVE_CATEGORIES = {"SMS", "Call log", "Microphone"}

# Special permissions that enable well-known mobile attack techniques.
SPECIAL_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW": "draw over other apps (tapjacking / overlay attacks)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install other APKs (dropper behaviour)",
    "android.permission.QUERY_ALL_PACKAGES": "list every installed app (fingerprinting)",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "full access to shared storage",
    "android.permission.READ_LOGS": "read system logs",
}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    detail: str
    recommendation: str
    component: str = "-"
    reference: str = "-"

    def to_dict(self):
        return asdict(self)


def _is_true(value):
    return str(value).lower() == "true"


# --------------------------------------------------------------------------
# Application-level flags
# --------------------------------------------------------------------------
def check_debuggable(m):
    if _is_true(m.attr(m.application, "debuggable")):
        return [Finding("APK-001", "Application is debuggable", "High",
                        "android:debuggable=\"true\" lets anyone with USB access attach a "
                        "debugger, read memory and run code as the app.",
                        "Remove android:debuggable or set it to false in release builds.",
                        reference="OWASP MASVS-RESILIENCE / CWE-489")]
    return []


def check_test_only(m):
    if _is_true(m.attr(m.application, "testOnly")):
        return [Finding("APK-002", "Application is marked testOnly", "Medium",
                        "android:testOnly=\"true\" means this is a development build "
                        "that should never be distributed.",
                        "Build a proper release variant before distribution.",
                        reference="OWASP MASVS-CODE")]
    return []


def check_backup(m):
    app = m.application
    value = m.attr(app, "allowBackup")
    if value is not None and not _is_true(value):
        return []
    has_rules = m.attr(app, "fullBackupContent") or m.attr(app, "dataExtractionRules")
    if has_rules:
        return [Finding("APK-003", "Backup enabled with custom rules", "Info",
                        "Backup is allowed but restricted by backup rules. Review the "
                        "rules file to confirm no secrets are included.",
                        "Exclude tokens, databases and keys from backup rules.",
                        reference="OWASP MASVS-STORAGE")]
    # Android 12 (API 31) stopped adb backup of app data for apps targeting 31+.
    severity = "Medium" if (m.target_sdk or 0) < 31 else "Low"
    how = "explicitly true" if value is not None else "not set (defaults to true)"
    return [Finding("APK-003", "allowBackup enabled", severity,
                    f"android:allowBackup is {how}. App data may be extracted with "
                    "'adb backup' or cloud backup.",
                    "Set android:allowBackup=\"false\" or define dataExtractionRules.",
                    reference="OWASP MASVS-STORAGE / CWE-530")]


def check_cleartext(m):
    app = m.application
    findings = []
    value = m.attr(app, "usesCleartextTraffic")
    nsc = m.attr(app, "networkSecurityConfig")
    if _is_true(value):
        findings.append(Finding("APK-004", "Cleartext (HTTP) traffic allowed", "Medium",
                                "android:usesCleartextTraffic=\"true\" allows unencrypted "
                                "HTTP, which can be sniffed or modified (MITM).",
                                "Use HTTPS only and set usesCleartextTraffic to false.",
                                reference="OWASP MASVS-NETWORK / CWE-319"))
    elif value is None and nsc is None and (m.target_sdk or 0) < 28:
        findings.append(Finding("APK-004", "Cleartext traffic allowed by default", "Medium",
                                f"targetSdkVersion {m.target_sdk} (< 28) permits HTTP "
                                "by default and no network security config is set.",
                                "Raise targetSdkVersion or add a network security config.",
                                reference="OWASP MASVS-NETWORK / CWE-319"))
    if nsc is not None:
        findings.append(Finding("APK-005", "Custom network security config present", "Info",
                                f"android:networkSecurityConfig points to {nsc}. It may "
                                "allow cleartext domains or user-installed CAs.",
                                "Review res/xml network security config manually.",
                                reference="OWASP MASVS-NETWORK"))
    return findings


# --------------------------------------------------------------------------
# Exported components (attack surface for other apps on the device)
# --------------------------------------------------------------------------
def _is_launcher(element):
    for intent in element.findall("intent-filter"):
        actions = {a.get("{http://schemas.android.com/apk/res/android}name")
                   for a in intent.findall("action")}
        cats = {c.get("{http://schemas.android.com/apk/res/android}name")
                for c in intent.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
            return True
    return False


def effective_exported(m, comp_type, element):
    """Work out if a component is exported, following Android's default rules.

    Returns (exported: bool, reason: str).
    """
    value = m.attr(element, "exported")
    if value is not None:
        return _is_true(value), "explicit android:exported=\"true\""
    if element.findall("intent-filter"):
        # Before API 31 a component with an intent-filter is exported by default.
        return True, "implicit (has intent-filter, no android:exported)"
    if comp_type == "provider" and (m.target_sdk or 0) < 17:
        return True, "implicit (provider with targetSdk < 17)"
    return False, ""


def _protection_levels(m):
    """Map custom permission name -> protectionLevel declared in this app."""
    levels = {}
    for perm in m.custom_permissions():
        name = m.attr(perm, "name")
        if name:
            levels[name] = (m.attr(perm, "protectionLevel") or "normal").lower()
    return levels


def check_exported_components(m):
    findings = []
    levels = _protection_levels(m)
    base_severity = {"provider": "High", "service": "Medium", "receiver": "Medium",
                     "activity": "Low", "activity-alias": "Low"}
    for comp_type, element in m.components():
        exported, reason = effective_exported(m, comp_type, element)
        if not exported or (comp_type.startswith("activity") and _is_launcher(element)):
            continue
        name = m.attr(element, "name") or "?"
        guard = m.attr(element, "permission")
        if comp_type == "provider":
            guard = guard or m.attr(element, "readPermission") or m.attr(element, "writePermission")

        if guard:
            level = levels.get(guard, "system/unknown")
            if level in ("normal", "dangerous"):
                findings.append(Finding("APK-006", f"Exported {comp_type} protected by weak permission",
                                        "Low",
                                        f"{reason}; guarded by {guard} with protectionLevel "
                                        f"'{level}', which any app can request.",
                                        "Use protectionLevel=\"signature\" for internal components.",
                                        component=name, reference="OWASP MASVS-PLATFORM / CWE-926"))
            continue

        severity = base_severity.get(comp_type, "Low")
        detail = f"{reason}; no permission required, so any installed app can call it."
        if comp_type == "provider" and _is_true(m.attr(element, "grantUriPermissions")):
            detail += " grantUriPermissions is also enabled."
        findings.append(Finding("APK-006", f"Unprotected exported {comp_type}", severity, detail,
                                "Set android:exported=\"false\" or require a signature-level "
                                "permission.",
                                component=name, reference="OWASP MASVS-PLATFORM / CWE-926"))
    return findings


# --------------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------------
def check_dangerous_permissions(m):
    requested = m.permissions()
    by_category = {}
    for perm in requested:
        if perm in DANGEROUS_PERMISSIONS:
            by_category.setdefault(DANGEROUS_PERMISSIONS[perm], []).append(perm)
    if not by_category:
        return []
    sensitive = SENSITIVE_CATEGORIES.intersection(by_category)
    severity = "Medium" if sensitive else "Low"
    count = sum(len(v) for v in by_category.values())
    summary = ", ".join(f"{cat} ({len(p)})" for cat, p in sorted(by_category.items()))
    detail = f"{count} dangerous permissions requested across: {summary}."
    if sensitive:
        detail += f" Highly sensitive groups: {', '.join(sorted(sensitive))}."
    return [Finding("APK-007", "Dangerous runtime permissions requested", severity, detail,
                    "Confirm each permission is required by a real feature; remove the rest.",
                    reference="OWASP MASVS-PRIVACY / CWE-250")]


def check_special_permissions(m):
    findings = []
    for perm in m.permissions():
        if perm in SPECIAL_PERMISSIONS:
            findings.append(Finding("APK-008", f"Special permission: {perm.split('.')[-1]}",
                                    "Medium",
                                    f"Allows the app to {SPECIAL_PERMISSIONS[perm]}.",
                                    "Justify this permission or remove it.",
                                    component=perm, reference="OWASP MASVS-PLATFORM"))
    return findings


# --------------------------------------------------------------------------
# SDK levels
# --------------------------------------------------------------------------
def check_sdk_levels(m):
    findings = []
    if m.target_sdk is not None and m.target_sdk < 24:
        findings.append(Finding("APK-009", "Trusts user-installed CA certificates", "Medium",
                                f"targetSdkVersion {m.target_sdk} (< 24) trusts user-added "
                                "CAs by default, making HTTPS interception easier.",
                                "Target API 24+ so only system CAs are trusted by default.",
                                reference="OWASP MASVS-NETWORK / CWE-295"))
    elif m.target_sdk is not None and m.target_sdk < 30:
        findings.append(Finding("APK-010", "Outdated targetSdkVersion", "Low",
                                f"targetSdkVersion {m.target_sdk} misses newer platform "
                                "security behaviour (scoped storage, package visibility).",
                                "Target a recent API level.",
                                reference="OWASP MASVS-CODE"))
    if m.min_sdk is not None and m.min_sdk < 21:
        findings.append(Finding("APK-011", "Very low minSdkVersion", "Low",
                                f"minSdkVersion {m.min_sdk} allows install on Android "
                                "versions that no longer receive security patches.",
                                "Raise minSdkVersion to 21 or higher if possible.",
                                reference="OWASP MASVS-CODE"))
    return findings


CHECKS = [
    ("Debuggable flag", check_debuggable),
    ("testOnly flag", check_test_only),
    ("Backup settings", check_backup),
    ("Network / cleartext traffic", check_cleartext),
    ("Exported components", check_exported_components),
    ("Dangerous permissions", check_dangerous_permissions),
    ("Special permissions", check_special_permissions),
    ("SDK levels", check_sdk_levels),
]


def risk_score(findings):
    """0-100 score from weighted severities, plus a text rating."""
    score = min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))
    if score >= 80:
        rating = "CRITICAL"
    elif score >= 50:
        rating = "HIGH"
    elif score >= 20:
        rating = "MEDIUM"
    else:
        rating = "LOW"
    return score, rating


def run_checks(manifest, killswitch=None, on_progress=None):
    """Run every check.

    Returns (findings, completed_checks, aborted). If the kill switch fires,
    the scan stops early but the findings collected so far are kept.
    """
    from .killswitch import AbortScan

    findings, completed, aborted = [], [], False
    for label, check in CHECKS:
        try:
            if killswitch:
                killswitch.check()
        except AbortScan:
            aborted = True
            break
        if on_progress:
            on_progress(label)
        findings.extend(check(manifest))
        completed.append(label)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings, completed, aborted
