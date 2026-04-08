package android.content

import android.net.ConnectivityManager
import android.os.BatteryManager

open class Context {
    companion object {
        const val CONNECTIVITY_SERVICE = "connectivity"
        const val BATTERY_SERVICE      = "battery"
    }
    fun getSystemService(name: String): Any? = when (name) {
        CONNECTIVITY_SERVICE -> ConnectivityManager()
        BATTERY_SERVICE      -> BatteryManager()
        else                 -> null
    }
}
