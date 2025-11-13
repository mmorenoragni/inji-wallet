package io.mosip.residentapp

import android.content.ComponentName
import android.content.Intent
import com.facebook.react.bridge.*

class IdPeruModule(private val reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {

    companion object {
        // Default configuration for RENIEC/IDPerú (fallback)
        private const val DEFAULT_PACKAGE_NAME = "pe.gob.reniec.pki.reniecidaas2"
        private const val DEFAULT_ACTIVITY_NAME = "pe.gob.reniec.feature.gateway.AppGatewayActivity"
        private const val DEFAULT_INPUT_KEY = "code"
        private const val RESULT_KEY = "auth_code"
    }

    override fun getName() = "IdPeruBridge"

    @ReactMethod
    fun startAuth(
        qrData: String,
        packageName: String,
        activityName: String,
        inputKey: String,
        promise: Promise
    ) {
        val activity = currentActivity as? MainActivity
        if (activity == null) {
            promise.reject("E_NO_ACTIVITY", "No current Activity")
            return
        }

        try {
            // Use provided configuration or fallback to defaults
            val finalPackageName = packageName.ifEmpty { DEFAULT_PACKAGE_NAME }
            val finalActivityName = activityName.ifEmpty { DEFAULT_ACTIVITY_NAME }
            val finalInputKey = inputKey.ifEmpty { DEFAULT_INPUT_KEY }

            // Validate required parameters
            if (qrData.isEmpty()) {
                promise.reject("E_INVALID_PARAMS", "qrData cannot be empty")
                return
            }

            // Check if IDPerú is installed
            if (!isPackageInstalled(finalPackageName)) {
                promise.reject("E_APP_NOT_INSTALLED", "IDPerú app is not installed")
                return
            }

            // Create Intent to launch IDPerú (following official RENIEC example)
            val intent = Intent().apply {
                component = ComponentName(finalPackageName, finalActivityName)
                putExtra(finalInputKey, qrData)
                // No flags - they interfere with ActivityResultLauncher
            }
            // Log everything before launching
            android.util.Log.d("IDPerú", "========== LAUNCHING IDPerú APP ==========")
            android.util.Log.d("IDPerú", "Package: $finalPackageName")
            android.util.Log.d("IDPerú", "Activity: $finalActivityName")
            android.util.Log.d("IDPerú", "Input Key Name: '$finalInputKey'")
            android.util.Log.d("IDPerú", "Input Value: '$qrData'")
            android.util.Log.d("IDPerú", "Input Value Length: ${qrData.length}")
            android.util.Log.d("IDPerú", "Starts with RENIEC_IDAAS: ${qrData.startsWith("RENIEC_IDAAS.")}")
            android.util.Log.d("IDPerú", "Intent: ${intent.toString()}")
            android.util.Log.d("IDPerú", "Intent Extras: ${intent.extras}")
            android.util.Log.d("IDPerú", "==========================================")
            // Launch IDPerú using MainActivity's launcher
            MainActivity.launchIdPeru(activity, intent, object : MainActivity.IdPeruResultListener {
                override fun onSuccess(authCode: String) {
                    promise.resolve(authCode)
                }

                override fun onCancel(reason: String) {
                    promise.reject("E_CANCELED", reason)
                }

                override fun onError(message: String) {
                    promise.reject("E_ERROR", message)
                }
            })
        } catch (e: Exception) {
            promise.reject("E_EXCEPTION", "Failed to start IDPerú auth: ${e.message}", e)
        }
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            reactContext.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: Exception) {
            false
        }
    }
}

