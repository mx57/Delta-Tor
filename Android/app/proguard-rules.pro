# Snowflake / gomobile bindings
-keep class snowflake.** { *; }
-keep class go.** { *; }

# Native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep DeltaTor classes
-keep class io.deltator.** { *; }

# AWG/WG tunnel + transitive optional refs (R8 missing_rules)
-dontwarn javax.annotation.Nonnull
-dontwarn javax.annotation.meta.TypeQualifierDefault
-dontwarn javax.lang.model.element.Modifier
-dontwarn javax.naming.**
-dontwarn org.slf4j.impl.StaticLoggerBinder
-dontwarn org.slf4j.impl.StaticMDCBinder
-dontwarn org.slf4j.impl.StaticMarkerBinder
-keep class org.amnezia.awg.** { *; }
-keep class com.wireguard.** { *; }

# BouncyCastle
-dontwarn org.bouncycastle.jce.provider.**
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.math.ec.rfc7748.** { *; }
