# Keep VLESS VPN classes
-keep class com.vlessvpn.** { *; }
-keep class com.musicses.vlessvpn.** { *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}
