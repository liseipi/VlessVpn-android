package com.musicses.vlessvpn;

import android.content.Context;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class Tun2Socks {

    private static final String TAG = "tun2socks";
    private static volatile boolean isInitialized = false;

    public static void initialize(Context context) {
        if (isInitialized) {
            Log.w(TAG, "initialization before done");
            return;
        }
        System.loadLibrary("tun2socks");
        isInitialized = true;
    }

    public static boolean startTun2Socks(
            LogLevel logLevel,
            ParcelFileDescriptor vpnInterfaceFileDescriptor,
            int vpnInterfaceMtu,
            String socksServerAddress,
            int socksServerPort,
            String netIPv4Address,
            @Nullable String netIPv6Address,
            String netmask,
            boolean forwardUdp) {

        ArrayList<String> arguments = new ArrayList<>();
        arguments.add("badvpn-tun2socks");
        arguments.addAll(Arrays.asList("--logger", "stdout"));
        arguments.addAll(Arrays.asList("--loglevel", String.valueOf(logLevel.ordinal())));
        arguments.addAll(Arrays.asList("--tunfd", String.valueOf(vpnInterfaceFileDescriptor.getFd())));
        arguments.addAll(Arrays.asList("--tunmtu", String.valueOf(vpnInterfaceMtu)));
        arguments.addAll(Arrays.asList("--netif-ipaddr", netIPv4Address));

        if (!TextUtils.isEmpty(netIPv6Address)) {
            arguments.addAll(Arrays.asList("--netif-ip6addr", netIPv6Address));
        }

        arguments.addAll(Arrays.asList("--netif-netmask", netmask));
        arguments.addAll(Arrays.asList(
                "--socks-server-addr",
                String.format(Locale.US, "%s:%d", socksServerAddress, socksServerPort)));

        if (forwardUdp) {
            arguments.add("--socks5-udp");
        }

        int exitCode = start_tun2socks(arguments.toArray(new String[]{}));
        return exitCode == 0;
    }

    private static native int start_tun2socks(String[] args);
    public static native void stopTun2Socks();
    public static native void printTun2SocksHelp();
    public static native void printTun2SocksVersion();

    public enum LogLevel {
        NONE, ERROR, WARNING, NOTICE, INFO, DEBUG
    }
}
