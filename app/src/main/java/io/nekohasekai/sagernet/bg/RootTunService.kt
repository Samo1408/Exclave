/*******************************************************************************
 *                                                                             *
 * RootTunService — TUN tunnel via root shell, no BIND_VPN_SERVICE needed.    *
 *                                                                             *
 * Strategy:                                                                   *
 *   1. su opens /dev/net/tun and does TUNSETIFF ioctl (all from root)        *
 *   2. su sends the open fd over a Unix domain socket via SCM_RIGHTS         *
 *   3. App receives fd via LocalSocket.ancillaryFileDescriptors               *
 *   4. Pass that fd to Libsagernetcore.newTun2ray() — same as VpnService     *
 *   5. Set up ip routes via root so all traffic flows through the tun        *
 *                                                                             *
 *******************************************************************************/

package io.nekohasekai.sagernet.bg

import android.annotation.SuppressLint
import android.app.Service
import android.content.Intent
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.Network
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.utils.DefaultNetworkListener
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import libsagernetcore.Libsagernetcore
import libsagernetcore.TunConfig
import libsagernetcore.Tun2ray
import java.io.DataOutputStream
import java.io.File
import java.io.FileDescriptor

class RootTunService : Service(),
    BaseService.Interface,
    LocalResolver {

    companion object {
        var instance: RootTunService? = null

        private const val TUN_NAME        = "exclave0"
        private const val TUN_IPV4        = "172.19.0.1"
        private const val TUN_IPV4_PREFIX = 30
        private const val TUN_DNS         = "172.19.0.2"
        private const val TUN_IPV6        = "fdfe:dcba:9876::1"
        private const val TUN_MTU         = 1500
    }

    override val data      = BaseService.Data(this)
    override val tag: String get() = "SagerNetRootTunService"
    override fun createNotification(profileName: String): ServiceNotification =
        ServiceNotification(this, profileName, "service-vpn", true)

    override var wakeLock: PowerManager.WakeLock? = null

    @Volatile
    override var underlyingNetwork: Network? = null

    private var tunPfd: ParcelFileDescriptor? = null
    private var tun: Tun2ray? = null

    // ────────────────────────────────────────────────
    // Lifecycle
    // ────────────────────────────────────────────────

    override suspend fun preInit() {
        DefaultNetworkListener.start(this) {
            SagerNet.reloadNetwork(it)
            underlyingNetwork = it
        }
    }

    override suspend fun startProcesses() {
        withContext(Dispatchers.IO) {
            startRootTun()
        }
        super.startProcesses()
    }

    @SuppressLint("WakelockTimeout")
    override fun acquireWakeLock() {
        wakeLock = SagerNet.power
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sagernet:roottun")
            .apply { acquire() }
    }

    override fun killProcesses() {
        data.proxy?.v2rayPoint?.withLocalResolver(null)
        tun?.apply { close() }
        tun = null
        tunPfd?.close()
        tunPfd = null
        super.killProcesses()
        instance = null
        GlobalScope.launch(Dispatchers.IO) {
            teardownTun()
            DefaultNetworkListener.stop(this)
        }
    }

    override fun onBind(intent: Intent) = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        super<BaseService.Interface>.onStartCommand(intent, flags, startId)

    override fun onDestroy() {
        super.onDestroy()
        data.binder.close()
    }

    // ────────────────────────────────────────────────
    // Main entry
    // ────────────────────────────────────────────────

    private suspend fun startRootTun() {
        instance = this
        if (!checkRoot()) throw SecurityException("Root access required for Root TUN mode")

        // مسار socket في private storage
        val socketPath = File(
            SagerNet.deviceStorage.noBackupFilesDir, "roottun.sock"
        ).absolutePath
        File(socketPath).delete()

        // أنشئ الـ interface بالروت أولاً
        setupTunInterface()

        // استقبل الـ fd عبر Unix socket
        val fd = receiveTunFd(socketPath)
        tunPfd = ParcelFileDescriptor.adoptFd(fd)
        Logs.i("RootTunService: tun fd=$fd")

        // setup الـ routing
        setupRouting()

        // مرر للـ core
        data.proxy!!.v2rayPoint.withLocalResolver(this)

        val config = TunConfig().apply {
            fileDescriptor      = tunPfd!!.fd
            protect             = false
            mtu                 = TUN_MTU
            discardICMP         = DataStore.discardICMP
            v2Ray               = data.proxy!!.v2rayPoint
            addr4               = TUN_IPV4
            addr6               = TUN_IPV6
            dns4                = TUN_DNS
            dns6                = ""
            enableIPv6          = false
            implementation      = DataStore.tunImplementation
            sniffing            = DataStore.trafficSniffing
            overrideDestination = DataStore.destinationOverride
            fakeDNS             = DataStore.enableFakeDns
            dumpUID             = data.proxy!!.config.dumpUID
            trafficStats        = DataStore.appTrafficStatistics
            pCap                = false
        }

        tun = Libsagernetcore.newTun2ray(config)
        Logs.i("RootTunService: tun2ray started on $TUN_NAME")
    }

    // ────────────────────────────────────────────────
    // TUN interface setup (root only)
    // ────────────────────────────────────────────────

    private suspend fun setupTunInterface() {
        val script = """
            ip tuntap del dev $TUN_NAME mode tun 2>/dev/null || true
            ip tuntap add dev $TUN_NAME mode tun
            ip addr flush dev $TUN_NAME 2>/dev/null || true
            ip addr add $TUN_IPV4/$TUN_IPV4_PREFIX dev $TUN_NAME
            ip link set $TUN_NAME mtu $TUN_MTU up
            echo IFACE_OK
        """.trimIndent()

        val out = runAsRoot(script)
        if (!out.contains("IFACE_OK"))
            throw RuntimeException("Failed to create tun interface:\n$out")
        Logs.i("RootTunService: interface $TUN_NAME created")
    }

    // ────────────────────────────────────────────────
    // FD passing via Unix domain socket (SCM_RIGHTS)
    // ────────────────────────────────────────────────

    /**
     * خطوات:
     *  1. الـ app يفتح LocalServerSocket وينتظر
     *  2. su + python يفتح /dev/net/tun، يعمل TUNSETIFF باسم exclave0،
     *     ثم يرسل الـ fd عبر SCM_RIGHTS
     *  3. الـ app يستقبل الـ fd من ancillaryFileDescriptors
     */
    private suspend fun receiveTunFd(socketPath: String): Int = withContext(Dispatchers.IO) {
        // الـ server socket يستمع على abstract namespace (@ prefix)
        val abstractName = "roottun_fd"

        val server = LocalServerSocket(abstractName)

        // شغّل الـ python script بـ su في background
        val pythonScript = buildPythonFdSender(abstractName)
        val suProc = Runtime.getRuntime().exec("su")
        val suOs = DataOutputStream(suProc.outputStream)
        suOs.writeBytes(pythonScript)
        suOs.writeBytes("\nexit\n")
        suOs.flush()

        // انتظر الاتصال (timeout 10 ثانية)
        server.localSocketAddress  // ensure bound
        // set accept timeout via the underlying impl
        val clientSock: LocalSocket
        try {
            clientSock = server.accept()
        } finally {
            server.close()
        }

        // استقبل الـ fd
        val fd = extractFd(clientSock)
        clientSock.close()

        suProc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
        fd
    }  // end withContext

    /**
     * بناء الـ Python script اللي يشتغل بـ su ويرسل الـ fd
     */
    private fun buildPythonFdSender(socketName: String): String = buildString {
        appendLine("python3 << 'PYEOF'")
        appendLine("import socket, array, fcntl, struct, os, time")
        appendLine("")
        appendLine("TUNSETIFF = 0x400454ca")
        appendLine("IFF_TUN   = 0x0001")
        appendLine("IFF_NO_PI = 0x1000")
        appendLine("")
        appendLine("# افتح /dev/net/tun بصلاحيات root")
        appendLine("tun_fd = os.open('/dev/net/tun', os.O_RDWR)")
        appendLine("")
        appendLine("# ربط الـ fd بالـ interface المنشأ مسبقاً")
        appendLine("ifr = struct.pack('16sH22x', b'$TUN_NAME', IFF_TUN | IFF_NO_PI)")
        appendLine("fcntl.ioctl(tun_fd, TUNSETIFF, ifr)")
        appendLine("")
        appendLine("# اتصل بالـ abstract Unix socket")
        appendLine("sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
        appendLine("sock.connect('\\0$socketName')")
        appendLine("")
        appendLine("# أرسل الـ fd عبر SCM_RIGHTS ancillary data")
        appendLine("fds = array.array('i', [tun_fd])")
        appendLine("sock.sendmsg([b'\\x01'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])")
        appendLine("sock.close()")
        appendLine("PYEOF")
        appendLine("echo PY_DONE")
    }

    /**
     * استخرج الـ fd من LocalSocket.ancillaryFileDescriptors
     */
    private fun extractFd(socket: LocalSocket): Int {
        // اقرأ الـ message عشان يتحمّل الـ ancillary data
        val buf = ByteArray(4)
        socket.inputStream.read(buf)

        val fds: Array<FileDescriptor>? = socket.ancillaryFileDescriptors
        if (fds.isNullOrEmpty()) {
            throw RuntimeException(
                "No fd received from root script. " +
                "Make sure python3 is available (via Magisk/BusyBox)."
            )
        }

        val intFdField = FileDescriptor::class.java.getDeclaredField("descriptor")
        intFdField.isAccessible = true
        val fdInt = intFdField.getInt(fds[0])

        Logs.i("RootTunService: received fd=$fdInt via SCM_RIGHTS")
        return fdInt
    }

    // ────────────────────────────────────────────────
    // Routing (root)
    // ────────────────────────────────────────────────

    private suspend fun setupRouting() {
        val script = """
            # routing: كل traffic يمر عبر $TUN_NAME
            ip rule del fwmark 1 table 100 2>/dev/null || true
            ip rule add fwmark 1 table 100 priority 100
            ip route flush table 100 2>/dev/null || true
            ip route add default dev $TUN_NAME table 100

            # علّم كل الـ OUTPUT بـ fwmark 1
            iptables -t mangle -D OUTPUT -j MARK --set-mark 1 2>/dev/null || true
            iptables -t mangle -I OUTPUT 1 -j MARK --set-mark 1

            echo ROUTING_OK
        """.trimIndent()

        val out = runAsRoot(script)
        if (!out.contains("ROUTING_OK"))
            throw RuntimeException("Failed to setup routing:\n$out")
        Logs.i("RootTunService: routing configured")
    }

    private suspend fun teardownTun() {
        val script = """
            iptables -t mangle -D OUTPUT -j MARK --set-mark 1 2>/dev/null || true
            ip rule del fwmark 1 table 100 2>/dev/null || true
            ip route flush table 100 2>/dev/null || true
            ip link set $TUN_NAME down 2>/dev/null || true
            ip tuntap del dev $TUN_NAME mode tun 2>/dev/null || true
            echo TEARDOWN_OK
        """.trimIndent()
        try {
            runAsRoot(script)
            Logs.i("RootTunService: teardown complete")
        } catch (e: Exception) {
            Logs.w("RootTunService: teardown error: ${e.message}")
        }
    }

    // ────────────────────────────────────────────────
    // Root shell helpers
    // ────────────────────────────────────────────────

    private suspend fun checkRoot(): Boolean = withContext(Dispatchers.IO) {
        try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
            out.contains("uid=0")
        } catch (e: Exception) { false }
    }

    private suspend fun runAsRoot(script: String): String = withContext(Dispatchers.IO) {
        val proc = Runtime.getRuntime().exec("su")
        val os   = DataOutputStream(proc.outputStream)
        os.writeBytes(script)
        os.writeBytes("\nexit\n")
        os.flush()
        os.close()
        val stdout = proc.inputStream.bufferedReader().readText()
        val stderr = proc.errorStream.bufferedReader().readText()
        proc.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)
        if (stderr.isNotEmpty()) Logs.w("su stderr: $stderr")
        stdout
    }
}
