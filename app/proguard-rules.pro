# Keep MediaPipe GenAI + protobuf classes used by the LLM Inference runtime.
-keep class com.google.mediapipe.** { *; }
-keep class com.google.protobuf.** { *; }
-dontwarn com.google.mediapipe.**

# kotlinx-serialization
-keepattributes *Annotation*, InnerClasses
-keepclassmembers class **$$serializer { *; }
-keepclasseswithmembers class com.mutationarena.mobile.** {
    kotlinx.serialization.KSerializer serializer(...);
}
