package com.cavadvpn.vpn

/**
 * Represents the current state of the VPN connection.
 */
sealed class VpnConnectionState {

    /** No active connection. */
    object Disconnected : VpnConnectionState()

    /** Currently establishing a connection. */
    object Connecting : VpnConnectionState()

    /**
     * Successfully connected.
     *
     * @property stats Live traffic statistics for the current session.
     */
    data class Connected(val stats: VpnStats) : VpnConnectionState()

    /**
     * The connection could not be established or was lost due to an error.
     *
     * @property message Human-readable error description.
     */
    data class Error(val message: String) : VpnConnectionState()
}
