# No project-specific keep rules needed: the app uses no reflection, and
# Compose / AndroidX ship their own consumer ProGuard rules.

# libadb-android pulls in BouncyCastle (bcprov) which references optional classes.
-dontwarn org.bouncycastle.**

# spake2-java registers its native methods by name (RegisterNatives): keep those names.
-keep class io.github.muntashirakon.crypto.spake2.** { *; }

# libadb-android loads Conscrypt by reflection (Class.forName), so R8 cannot see these uses: keep them.
# OpenSSLProvider supplies TLS 1.3; Conscrypt.exportKeyingMaterial is what pairing needs.
-keep class org.conscrypt.OpenSSLProvider { <init>(); }
-keep class org.conscrypt.Conscrypt { public static byte[] exportKeyingMaterial(javax.net.ssl.SSLSocket, java.lang.String, byte[], int); }
-dontwarn org.conscrypt.**
