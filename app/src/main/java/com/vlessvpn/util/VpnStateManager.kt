package com.vlessvpn.util

import androidx.lifecycle.MutableLiveData

/**
 * VPN 状态全局管理
 */
object VpnStateManager {

    enum class State {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        DISCONNECTING,
        ERROR
    }

    val state = MutableLiveData(State.DISCONNECTED)
    val errorMessage = MutableLiveData<String?>()

    fun setState(s: State, error: String? = null) {
        state.postValue(s)
        if (error != null) errorMessage.postValue(error)
    }
}
