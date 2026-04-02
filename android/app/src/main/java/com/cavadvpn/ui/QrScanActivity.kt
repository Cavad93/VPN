package com.cavadvpn.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.cavadvpn.R
import com.cavadvpn.config.ConfigStore
import com.cavadvpn.config.QrConfig
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.nio.ByteBuffer
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

private const val TAG = "QrScanActivity"

/**
 * Activity that scans a QR code using CameraX and ZXing.
 *
 * On a successful scan, the configuration is parsed with [QrConfig.parseQrCode],
 * saved with [ConfigStore.save], and the activity finishes with [RESULT_OK].
 */
class QrScanActivity : AppCompatActivity() {

    private lateinit var previewView: PreviewView
    private lateinit var tvHint: TextView
    private lateinit var btnCancel: Button

    private lateinit var cameraExecutor: ExecutorService
    private var scanDone = false

    // -----------------------------------------------------------------------
    // Camera permission launcher
    // -----------------------------------------------------------------------

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            startCamera()
        } else {
            Toast.makeText(this, getString(R.string.qr_camera_permission_denied), Toast.LENGTH_LONG).show()
            setResult(RESULT_CANCELED)
            finish()
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scan)

        previewView = findViewById(R.id.previewView)
        tvHint      = findViewById(R.id.tvQrHint)
        btnCancel   = findViewById(R.id.btnQrCancel)

        cameraExecutor = Executors.newSingleThreadExecutor()

        btnCancel.setOnClickListener {
            setResult(RESULT_CANCELED)
            finish()
        }

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED) {
            startCamera()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    // -----------------------------------------------------------------------
    // Camera
    // -----------------------------------------------------------------------

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            val imageAnalysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor, QrCodeAnalyzer { text ->
                        if (!scanDone) {
                            scanDone = true
                            handleScanResult(text)
                        }
                    })
                }

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    this,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalysis
                )
            } catch (e: Exception) {
                Log.e(TAG, "Camera bind failed: ${e.message}", e)
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun handleScanResult(text: String) {
        runOnUiThread {
            try {
                val config = QrConfig.parseQrCode(text)
                val prefs  = getSharedPreferences("vpn_config", Context.MODE_PRIVATE)
                ConfigStore.save(prefs, config)

                val resultIntent = Intent().apply {
                    putExtra("server_host", config.serverHost)
                    putExtra("server_port", config.serverPort)
                }
                setResult(RESULT_OK, resultIntent)
                Toast.makeText(this, getString(R.string.qr_scan_success), Toast.LENGTH_SHORT).show()
            } catch (e: IllegalArgumentException) {
                Log.e(TAG, "Invalid QR config: ${e.message}")
                Toast.makeText(this, getString(R.string.qr_scan_invalid), Toast.LENGTH_LONG).show()
                scanDone = false // allow retry
                return@runOnUiThread
            }
            finish()
        }
    }
}

// -----------------------------------------------------------------------
// ZXing image analyser
// -----------------------------------------------------------------------

private class QrCodeAnalyzer(private val onResult: (String) -> Unit) : ImageAnalysis.Analyzer {

    private val reader = MultiFormatReader()

    override fun analyze(image: ImageProxy) {
        val buffer = image.planes[0].buffer
        val bytes  = buffer.toByteArray()
        val width  = image.width
        val height = image.height

        val source = PlanarYUVLuminanceSource(
            bytes, width, height, 0, 0, width, height, false
        )
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        try {
            val result = reader.decode(bitmap)
            onResult(result.text)
        } catch (_: NotFoundException) {
            // no QR code found in this frame — ignore
        } finally {
            image.close()
        }
    }

    private fun ByteBuffer.toByteArray(): ByteArray {
        rewind()
        val data = ByteArray(remaining())
        get(data)
        return data
    }
}
