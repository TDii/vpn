package com.example.httploggervpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.example.httploggervpn.databinding.ActivityMainBinding // 自动生成的 ViewBinding 类

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Log.i("MainActivity", "VPN permission granted by user.")
            startVpnService()
        } else {
            Log.w("MainActivity", "VPN permission denied by user.")
            // Optionally, show a message to the user explaining why the permission is needed
            updateButtonState()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.vpnToggleButton.setOnClickListener {
            toggleVpn()
        }
        // Initial state update will be covered by onResume
    }

    override fun onResume() {
        super.onResume()
        // Update button state in case the service was stopped from notification or other means
        // or if the activity is being recreated.
        updateButtonState()
    }

    private fun toggleVpn() {
        if (HttpLoggerVpnService.isRunning) {
            Log.d("MainActivity", "Attempting to stop VPN service.")
            HttpLoggerVpnService.stopVpnService(this)
        } else {
            Log.d("MainActivity", "Attempting to start VPN service.")
            val prepareIntent: Intent? = VpnService.prepare(this)
            if (prepareIntent == null) {
                // Permission already granted
                Log.i("MainActivity", "VPN permission already granted.")
                startVpnService()
            } else {
                // Permission needed
                Log.i("MainActivity", "Requesting VPN permission.")
                vpnPermissionLauncher.launch(prepareIntent)
            }
        }
        // Give a small delay for service state to potentially update before refreshing UI.
        // A more robust solution involves LocalBroadcastManager or observing LiveData from the service.
        binding.vpnToggleButton.postDelayed({ updateButtonState() }, 500)
    }

    private fun startVpnService() {
        HttpLoggerVpnService.startVpnService(this)
        // updateButtonState() // Called via postDelayed in toggleVpn to allow service state to settle
    }

    private fun updateButtonState() {
        if (HttpLoggerVpnService.isRunning) {
            binding.vpnToggleButton.text = "Stop VPN"
            // Optionally change icon or style: binding.vpnToggleButton.setIconResource(R.drawable.ic_stop)
        } else {
            binding.vpnToggleButton.text = "Start VPN"
            // Optionally change icon or style: binding.vpnToggleButton.setIconResource(R.drawable.ic_play_arrow)
        }
    }
}
