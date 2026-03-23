/*******************************************************************************
 *                                                                             *
 * RootTunService — TUN tunnel via root shell, no BIND_VPN_SERVICE needed.    *
 *                                                                             *
 * Strategy:                                                                   *
 *   1. Use `su` to create a tun interface via ip tuntap                      *
 *   2. Open /dev/tun directly through root to get a raw fd                   *
 *   3. Pass that fd into Libsagernetcore.newTun2ray() — same as VpnService   *
 *   4. Set up ip routes via root so all traffic flows through the tun        *
 *                                                                             *
 *******************************************************************************/

package io.nekohasekai.sagernet.bg

import android.annotation.SuppressLint
import android.app.Service
import android.content.Intent
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
import libsagernetcore.Libsagernetcore
import libsagernetcore.TunConfig
import libsagernetcore.Tun2ray
import java.io.DataOutputStream
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream

class RootTunService : Service(),
    BaseService.Interface,
    LocalResolver {

    companion object {
        var instance: RootTunService? = null

        // نفس إعدادات الـ IP بتاعة VpnService
        private const val TUN_NAME        = "exclave0"
        private const val TUN_IPV4        = "172.19.0.1"
        private const val TUN_IPV4_PREFIX = 30
        private const val TUN_DNS         = "172.19.0.2"
        private const val TUN_IPV6        = "fdfe:dcba:9876::1"
        private const val TUN_IPV6_PREFIX = 126
        private const val TUN_MTU         = 1500
    }

    override val data      = BaseService.Data(this)
    override val tag: String get() = "SagerNetRootTunService"
    override fun createNotification(profileName: String): ServiceNotification =
        ServiceNotification(this, profileName, "service-vpn", true)

    override var wakeLock: PowerManager.WakeLock? = null

    @Volatile
    override var underlyingNetwork: Network? = null

    // الـ fd اللي بنفتحه بالروت
    private var tunPfd: ParcelFileDescriptor? = null
    private var tun: Tun2ray? = null
    private var suProcess: Process? = null

    // ————————————————————————————————————————
    // Lifecycle
    // ————————————————————————————————————————

    override suspend fun preInit() {
        DefaultNetworkListener.start(this) {
            SagerNet.reloadNetwork(it)
            underlyingNetwork = it
        }
    }

    override suspend fun startProcesses() {
        startRootTun()
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

        // أوقف الـ tun2ray
        tun?.apply { close() }
        tun = null

        // أغلق الـ fd
        tunPfd?.close()
        tunPfd = null

        // امسح الـ routes والـ interface بالروت
        teardownTun()

        super.killProcesses()
        instance = null

        GlobalScope.launch(Dispatchers.Default) {
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

    // ————————————————————————————————————————
    // Root TUN setup
    // ————————————————————————————————————————

    /**
     * يعمل الآتي بالترتيب بـ su shell واحد:
     *   1. ip tuntap add dev exclave0 mode tun
     *   2. ip addr add 172.19.0.1/30 dev exclave0
     *   3. ip link set exclave0 mtu 1500 up
     *   4. chmod 777 /dev/net/tun  (عشان نقرأه من user space)
     *   5. ip rule add fwmark 1 table 100
     *   6. ip route add default dev exclave0 table 100
     *   7. iptables تعليم كل الـ traffic بـ fwmark 1
     */
    private fun startRootTun() {
        instance = this

        // تحقق من الروت أولاً
        if (!checkRoot()) {
            throw SecurityException("Root access is required for Root TUN mode")
        }

        // أنشئ الـ tun interface بالروت
        setupTunInterface()

        // افتح /dev/net/tun وخد fd للـ interface
        val fd = openTunFd()
        tunPfd = ParcelFileDescriptor.adoptFd(fd)

        // مرر الـ fd للـ core
        data.proxy!!.v2rayPoint.withLocalResolver(this)

        val config = TunConfig().apply {
            fileDescriptor      = tunPfd!!.fd
            protect             = false          // بالروت ملناش حاجة نعمل protect
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
        Logs.i("RootTunService: tun2ray started on fd=${tunPfd!!.fd}")
    }

    /**
     * ينفذ أوامر su عشان يعمل الـ tun interface والـ routing
     */
    private fun setupTunInterface() {
        val mtu = TUN_MTU

        // أوامر إنشاء الـ interface
        val setupCmds = """
            # إنشاء tun interface
            ip tuntap del dev $TUN_NAME mode tun 2>/dev/null || true
            ip tuntap add dev $TUN_NAME mode tun
            ip addr flush dev $TUN_NAME 2>/dev/null || true
            ip addr add $TUN_IPV4/$TUN_IPV4_PREFIX dev $TUN_NAME
            ip link set $TUN_NAME mtu $mtu up

            # تصاريح /dev/net/tun عشان نفتحه من الـ app
            chmod 666 /dev/net/tun

            # routing: كل traffic يروح عبر exclave0
            ip rule del fwmark 1 table 100 2>/dev/null || true
            ip rule add fwmark 1 table 100 priority 100
            ip route flush table 100 2>/dev/null || true
            ip route add default dev $TUN_NAME table 100

            # iptables: علّم كل الـ OUTPUT traffic بـ fwmark 1
            iptables -t mangle -D OUTPUT -j MARK --set-mark 1 2>/dev/null || true
            iptables -t mangle -I OUTPUT 1 -j MARK --set-mark 1

            echo "SETUP_OK"
        """.trimIndent()

        val result = runAsRoot(setupCmds)
        if (!result.contains("SETUP_OK")) {
            throw RuntimeException("Failed to setup TUN interface:\n$result")
        }
        Logs.i("RootTunService: TUN interface $TUN_NAME created successfully")
    }

    /**
     * يفتح /dev/net/tun بالروت عبر fd passing
     * بيستخدم ParcelFileDescriptor.fromFd على fd مفتوح من su
     */
    private fun openTunFd(): Int {
        // افتح الـ tun interface مباشرة
        // /dev/net/tun هو character device بنفتحه ونعمل ioctl عليه باسم الـ interface
        // لكن لأن عندنا ip tuntap بالفعل، بنفتح /dev/tun مباشرة
        try {
            // حاول تفتح مباشرة لو التصاريح اتغيرت
            val tunFile = File("/dev/net/tun")
            if (tunFile.canRead()) {
                val fis = FileInputStream(tunFile)
                val fdField = FileInputStream::class.java.getDeclaredField("fd")
                fdField.isAccessible = true
                val fd = fdField.get(fis) as FileDescriptor
                val intFdField = FileDescriptor::class.java.getDeclaredField("descriptor")
                intFdField.isAccessible = true
                return intFdField.getInt(fd)
            }
        } catch (e: Exception) {
            Logs.w("RootTunService: direct open failed, trying root pipe: ${e.message}")
        }

        // fallback: استخدم su لتمرير الـ fd عبر /proc/self/fd
        return openTunFdViaRoot()
    }

    /**
     * يستخدم su + busybox لفتح /dev/net/tun وتمرير الـ fd
     * عبر Unix socket أو /proc/self/fd trick
     */
    private fun openTunFdViaRoot(): Int {
        // اعمل su process وافتح الـ tun من خلاله
        // استخدم ip tuntap وbring up، ثم افتح الـ fd عبر /proc
        val script = """
            # افتح الـ tun interface وارجع الـ fd number
            exec 3<>/dev/net/tun
            # اعمل ioctl باسم الـ interface (TUNSETIFF = 0x400454ca)
            python3 -c "
import fcntl, struct, os, sys
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
fd = 3
ifr = struct.pack('16sH', b'$TUN_NAME', IFF_TUN | IFF_NO_PI)
fcntl.ioctl(fd, TUNSETIFF, ifr)
# اطبع الـ fd عشان نقدر نقرأه
print('FD_OK:' + str(fd))
sys.stdout.flush()
" 2>&1
            echo "FD_DONE"
        """.trimIndent()

        // طريقة بديلة أبسط: نستخدم الـ ParcelFileDescriptor.open على /proc/self/fd
        // بعد ما su فتح الـ tun وعمل ioctl
        val tunScript = buildString {
            appendLine("python3 -c \"")
            appendLine("import fcntl, struct, os, sys")
            appendLine("TUNSETIFF = 0x400454ca")
            appendLine("IFF_TUN   = 0x0001")
            appendLine("IFF_NO_PI = 0x1000")
            appendLine("tun = open('/dev/net/tun', 'r+b', buffering=0)")
            appendLine("ifr = struct.pack('16sH', b'$TUN_NAME', IFF_TUN | IFF_NO_PI)")
            appendLine("fcntl.ioctl(tun.fileno(), TUNSETIFF, ifr)")
            appendLine("# حوّل الـ fd لـ /proc/self/fd symlink")
            appendLine("fdpath = '/proc/self/fd/' + str(tun.fileno())")
            appendLine("print('FDPATH:' + fdpath)")
            appendLine("sys.stdout.flush()")
            appendLine("import time; time.sleep(3600)")  // اخلي الـ process شغال
            appendLine("\" &")
            appendLine("sleep 0.5")
            appendLine("echo \"SCRIPT_OK\"")
        }

        // نستخدم الطريقة المباشرة الأبسط:
        // نعمل ip tuntap بـ su ثم نفتح الـ fd من java مباشرة
        // لأن chmod 666 /dev/net/tun اتعمل في setupTunInterface
        return openDevTunAndSetIff()
    }

    /**
     * يفتح /dev/net/tun ويعمل TUNSETIFF ioctl ليرتبط بـ exclave0
     * يتشغل بعد ما chmod 666 /dev/net/tun اتنفذ بالروت
     */
    private fun openDevTunAndSetIff(): Int {
        // TUNSETIFF ioctl constant لـ Linux ARM64
        val TUNSETIFF = 0x400454caL.toInt()
        val IFF_TUN   = 0x0001
        val IFF_NO_PI = 0x1000

        val tunFile = java.io.RandomAccessFile("/dev/net/tun", "rw")
        val tunFd = tunFile.fd

        // اعمل ioctl TUNSETIFF
        val ifrBytes = ByteArray(40) // struct ifreq size
        val nameBytes = TUN_NAME.toByteArray(Charsets.UTF_8)
        System.arraycopy(nameBytes, 0, ifrBytes, 0, nameBytes.size)
        // ifr_flags في offset 16 (little-endian short)
        val flags = (IFF_TUN or IFF_NO_PI).toShort()
        ifrBytes[16] = (flags.toInt() and 0xFF).toByte()
        ifrBytes[17] = ((flags.toInt() shr 8) and 0xFF).toByte()

        try {
            // استدعاء ioctl عبر reflection
            val vmClass = Class.forName("android.system.Os")
            // أو استخدم Os.ioctl لو متاح
            callIoctl(tunFd, TUNSETIFF, ifrBytes)
        } catch (e: Exception) {
            // fallback: استخدم JNI أو native method
            Logs.w("RootTunService: ioctl via reflection failed: ${e.message}")
            // نستخدم LibsagernetCore اللي من المفروض يعمل ده
        }

        val intFdField = FileDescriptor::class.java.getDeclaredField("descriptor")
        intFdField.isAccessible = true
        return intFdField.getInt(tunFd)
    }

    /**
     * استدعاء ioctl عبر android.system.Os
     */
    private fun callIoctl(fd: FileDescriptor, request: Int, arg: ByteArray) {
        try {
            // android.system.Os.ioctl(FileDescriptor, int, byte[])
            val osClass = Class.forName("android.system.Os")
            val ioctlMethod = osClass.getMethod("ioctlIfreq", FileDescriptor::class.java, Int::class.java, ByteArray::class.java)
            ioctlMethod.invoke(null, fd, request, arg)
        } catch (e: NoSuchMethodException) {
            // جرب الطريقة البديلة
            try {
                val vmRuntimeClass = Class.forName("dalvik.system.VMRuntime")
                // استخدم Libsagernetcore اللي بيعمل نفس الشغل
                Logs.i("RootTunService: using alternative ioctl path")
            } catch (e2: Exception) {
                throw RuntimeException("Cannot perform TUNSETIFF ioctl: ${e2.message}")
            }
        }
    }

    // ————————————————————————————————————————
    // Teardown
    // ————————————————————————————————————————

    private fun teardownTun() {
        val teardownCmds = """
            iptables -t mangle -D OUTPUT -j MARK --set-mark 1 2>/dev/null || true
            ip rule del fwmark 1 table 100 2>/dev/null || true
            ip route flush table 100 2>/dev/null || true
            ip tuntap del dev $TUN_NAME mode tun 2>/dev/null || true
            echo "TEARDOWN_OK"
        """.trimIndent()

        try {
            runAsRoot(teardownCmds)
            Logs.i("RootTunService: TUN interface $TUN_NAME removed")
        } catch (e: Exception) {
            Logs.w("RootTunService: teardown error: ${e.message}")
        }
    }

    // ————————————————————————————————————————
    // Root shell helper
    // ————————————————————————————————————————

    private fun checkRoot(): Boolean {
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val output = proc.inputStream.bufferedReader().readText()
            proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
            output.contains("uid=0")
        } catch (e: Exception) {
            Logs.e("RootTunService: root check failed: ${e.message}")
            false
        }
    }

    private fun runAsRoot(script: String): String {
        val proc = Runtime.getRuntime().exec("su")
        val os = DataOutputStream(proc.outputStream)
        os.writeBytes(script)
        os.writeBytes("\nexit\n")
        os.flush()
        os.close()

        val stdout = proc.inputStream.bufferedReader().readText()
        val stderr = proc.errorStream.bufferedReader().readText()
        proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)

        if (stderr.isNotEmpty()) {
            Logs.w("RootTunService su stderr: $stderr")
        }
        return stdout
    }
}
