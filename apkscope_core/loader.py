"""Loads the AndroidManifest.xml from an APK (via androguard) or from a
decoded manifest XML file (e.g. produced by apktool, or the bundled sample).

Every loader returns the same Manifest object, so the checks do not care
where the manifest came from.
"""

import os
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


class LoadError(Exception):
    pass


class Manifest:
    """Thin wrapper around the manifest XML root with helper methods."""

    def __init__(self, root, source, meta=None):
        self.root = root
        self.source = source
        meta = meta or {}
        uses_sdk = root.find("uses-sdk")
        app = self.application

        self.package = meta.get("package") or root.get("package") or "unknown"
        self.version_name = (meta.get("version_name")
                             or root.get(ANDROID_NS + "versionName") or "unknown")
        self.version_code = (meta.get("version_code")
                             or root.get(ANDROID_NS + "versionCode") or "unknown")
        self.app_name = (meta.get("app_name")
                         or (app.get(ANDROID_NS + "label") if app is not None else None)
                         or "unknown")
        self.min_sdk = _to_int(meta.get("min_sdk")
                               or (uses_sdk.get(ANDROID_NS + "minSdkVersion")
                                   if uses_sdk is not None else None))
        self.target_sdk = _to_int(meta.get("target_sdk")
                                  or (uses_sdk.get(ANDROID_NS + "targetSdkVersion")
                                      if uses_sdk is not None else None))
        # Android uses minSdk as targetSdk when targetSdk is not declared.
        if self.target_sdk is None:
            self.target_sdk = self.min_sdk

    @property
    def application(self):
        return self.root.find("application")

    def attr(self, element, name):
        """Read an android:<name> attribute from an element (or None)."""
        if element is None:
            return None
        return element.get(ANDROID_NS + name)

    def permissions(self):
        perms = [e.get(ANDROID_NS + "name") for e in self.root.findall("uses-permission")]
        perms += [e.get(ANDROID_NS + "name") for e in self.root.findall("uses-permission-sdk-23")]
        return sorted({p for p in perms if p})

    def custom_permissions(self):
        return self.root.findall("permission")

    def components(self):
        """Yield (type, element) for every app component."""
        app = self.application
        if app is None:
            return
        for comp_type in ("activity", "activity-alias", "service", "receiver", "provider"):
            for element in app.findall(comp_type):
                yield comp_type, element


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_manifest_xml(path):
    """Load a plain-text (decoded) AndroidManifest.xml file."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise LoadError(f"Not a valid manifest XML file: {exc}") from exc
    if root.tag != "manifest":
        raise LoadError("XML root element is not <manifest>.")
    return Manifest(root, source=path)


def load_apk(path):
    """Load an APK with androguard and return its decoded manifest."""
    try:
        from androguard.core.apk import APK
    except ImportError as exc:
        raise LoadError("androguard is not installed. Run: pip install -r requirements.txt") from exc

    try:  # androguard 4 logs very noisily through loguru; silence it
        from loguru import logger
        logger.remove()
    except Exception:
        pass

    try:
        apk = APK(path)
        root = apk.get_android_manifest_xml()
    except Exception as exc:
        raise LoadError(f"Could not parse APK (XAPK / split APKs are not supported): {exc}") from exc
    if root is None:
        raise LoadError("APK has no readable AndroidManifest.xml.")

    meta = {}
    for key, getter in (("package", apk.get_package),
                        ("app_name", apk.get_app_name),
                        ("version_name", apk.get_androidversion_name),
                        ("version_code", apk.get_androidversion_code),
                        ("min_sdk", apk.get_min_sdk_version),
                        ("target_sdk", apk.get_target_sdk_version)):
        try:
            meta[key] = getter()
        except Exception:  # missing attributes must not crash the scan
            meta[key] = None
    return Manifest(root, source=path, meta=meta)


def load_target(path):
    """Pick the right loader based on the file extension."""
    if not os.path.isfile(path):
        raise LoadError(f"File not found: {path}")
    ext = os.path.splitext(path)[1].lower()
    if ext == ".xml":
        return load_manifest_xml(path)
    if ext == ".apk":
        return load_apk(path)
    raise LoadError("Unsupported file type. Use an .apk or a decoded AndroidManifest .xml file.")
