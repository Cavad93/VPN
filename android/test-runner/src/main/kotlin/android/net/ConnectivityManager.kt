package android.net

class ConnectivityManager {
    val activeNetwork: Network? = null
    fun getNetworkCapabilities(n: Network): NetworkCapabilities? = null
}

class Network
class NetworkCapabilities {
    companion object {
        const val TRANSPORT_WIFI      = 1
        const val TRANSPORT_CELLULAR  = 2
        const val TRANSPORT_ETHERNET  = 3
        const val TRANSPORT_VPN       = 4
    }
    fun hasTransport(t: Int): Boolean = false
}
