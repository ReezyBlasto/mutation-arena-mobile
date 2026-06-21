package com.mutationarena.mobile.model

import android.content.Context
import com.google.mediapipe.tasks.genai.llminference.LlmInference
import com.google.mediapipe.tasks.genai.llminference.LlmInference.LlmInferenceOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Wraps one on-device fine-tuned Gemma model via the MediaPipe LLM Inference API.
 *
 * The model is a Gemma `.task` file produced by the desktop Mutation Arena's
 * fine-tuning pipeline (LoRA → MediaPipe conversion). MediaPipe loads from a
 * FILE PATH, so a bundled asset is copied to internal storage on first use.
 * If the file is absent (not yet trained/installed), [isInstalled] is false and
 * [generate] returns null — the app still works, it just can't produce a signal.
 *
 * @param assetName e.g. "scout.task" under app/src/main/assets/models/
 */
class GemmaModel(
    private val context: Context,
    private val assetName: String,
    private val maxTokens: Int = 512,
    private val temperature: Float = 0.6f,
    private val topK: Int = 40,
) {
    private var engine: LlmInference? = null

    /** True if the model file exists either in internal storage or bundled assets. */
    val isInstalled: Boolean
        get() = internalFile().exists() || assetExists()

    private fun internalFile(): File = File(context.filesDir, "models/$assetName")

    private fun assetExists(): Boolean = try {
        context.assets.open("models/$assetName").use { true }
    } catch (_: Exception) {
        false
    }

    /** Copy the bundled asset to internal storage once, so MediaPipe can mmap it. */
    private fun ensureLocalCopy(): File? {
        val dst = internalFile()
        if (dst.exists()) return dst
        if (!assetExists()) return null
        dst.parentFile?.mkdirs()
        context.assets.open("models/$assetName").use { input ->
            dst.outputStream().use { output -> input.copyTo(output, 1 shl 20) }
        }
        return dst
    }

    private fun ensureEngine(): LlmInference? {
        engine?.let { return it }
        val path = ensureLocalCopy()?.absolutePath ?: return null
        val options = LlmInferenceOptions.builder()
            .setModelPath(path)
            .setMaxTokens(maxTokens)
            .setTemperature(temperature)
            .setTopK(topK)
            .build()
        return LlmInference.createFromOptions(context, options).also { engine = it }
    }

    /** Run a prompt on-device. Returns null if the model isn't installed. */
    suspend fun generate(prompt: String): String? = withContext(Dispatchers.Default) {
        val e = ensureEngine() ?: return@withContext null
        runCatching { e.generateResponse(prompt) }.getOrNull()
    }

    fun close() {
        runCatching { engine?.close() }
        engine = null
    }
}
