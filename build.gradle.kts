// Top-level build file
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android)      apply false   // ✅ 新增
    alias(libs.plugins.kotlin.compose)      apply false
}
