package main

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "math"
    "net"
    "os"
    //"os/exec"
    "os/signal"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "serverstatus-client/config"
    "serverstatus-client/metrics"
    "serverstatus-client/network"
)

// Global variables
var (
    cfg             *config.Configuration
    pingStats       map[string]*network.PingStatistics
    monitorServers  map[string]map[string]interface{}
    monitorMutex    sync.Mutex
    networkSpeed    struct {
        NetRx    int
        NetTx    int
        AvgRx    int64
        AvgTx    int64
        Clock    float64
        Diff     float64
        mu       sync.Mutex
    }
    diskIO struct {
        Read  int64
        Write int64
        mu    sync.Mutex
    }
)

func init() {
    // Parse command line flags
    var serverFlag, userFlag, passwordFlag string
    var portFlag, intervalFlag int

    flag.StringVar(&serverFlag, "server", "", "Server address")
    flag.IntVar(&portFlag, "port", 0, "Server port")
    flag.StringVar(&userFlag, "user", "", "Username")
    flag.StringVar(&passwordFlag, "password", "", "Password")
    flag.IntVar(&intervalFlag, "interval", 0, "Update interval in seconds")
    flag.Parse()

    // Initialize configuration
    cfg = config.DefaultConfig()
    
    // Override with command line flags if provided
    if serverFlag != "" {
        cfg.Server = serverFlag
    }
    if portFlag != 0 {
        cfg.Port = portFlag
    }
    if userFlag != "" {
        cfg.User = userFlag
    }
    if passwordFlag != "" {
        cfg.Password = passwordFlag
    }
    if intervalFlag != 0 {
        cfg.Interval = intervalFlag
    }

    // Initialize global variables
    pingStats = make(map[string]*network.PingStatistics)
    pingStats["10010"] = &network.PingStatistics{}
    pingStats["189"] = &network.PingStatistics{}
    pingStats["10086"] = &network.PingStatistics{}
    
    monitorServers = make(map[string]map[string]interface{})
}

func main() {
    // Set up signal handling for graceful shutdown
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    
    // Start background monitoring threads
    startMonitoringThreads()
    
    // Main connection loop
    for {
        select {
        case <-sigCh:
            log.Println("Shutting down...")
            return
        default:
            if err := connectAndReport(); err != nil {
                log.Printf("Error: %v", err)
                time.Sleep(3 * time.Second)
            }
        }
    }
}

func startMonitoringThreads() {
    // Start ping monitoring
    network.StartPingThread(cfg.CU, pingStats["10010"], cfg.ProbePort, cfg.Interval, cfg.ProbeProtocolPrefer == "ipv4")
    network.StartPingThread(cfg.CT, pingStats["189"], cfg.ProbePort, cfg.Interval, cfg.ProbeProtocolPrefer == "ipv4")
    network.StartPingThread(cfg.CM, pingStats["10086"], cfg.ProbePort, cfg.Interval, cfg.ProbeProtocolPrefer == "ipv4")
    
    // Start network speed monitoring
    go monitorNetworkSpeed()
    
    // Start disk I/O monitoring
    go monitorDiskIO()
}

func connectAndReport() error {
    log.Println("Connecting to server...")
    
    // Connect to the server
    conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Server, cfg.Port))
    if err != nil {
        return fmt.Errorf("connection failed: %v", err)
    }
    defer conn.Close()
    
    // Handle authentication
    reader := bufio.NewReader(conn)
    data, err := reader.ReadString('\n')
    if err != nil {
        return fmt.Errorf("read error: %v", err)
    }
    
    if strings.Contains(data, "Authentication required") {
        _, err = conn.Write([]byte(cfg.User + ":" + cfg.Password + "\n"))
        if err != nil {
            return fmt.Errorf("authentication failed: %v", err)
        }
        
        data, err = reader.ReadString('\n')
        if err != nil {
            return fmt.Errorf("read error after auth: %v", err)
        }
        
        if !strings.Contains(data, "Authentication successful") {
            return fmt.Errorf("authentication rejected: %s", data)
        }
    }
    
    log.Println("Connected and authenticated")
    
    // Check for IPv4/IPv6 preference
    checkIP := 0
    if strings.Contains(data, "IPv4") {
        checkIP = 6
    } else if strings.Contains(data, "IPv6") {
        checkIP = 4
    }
    
    // Process monitor configuration
    if !strings.Contains(data, "You are connecting via") {
        data, err = reader.ReadString('\n')
        if err != nil {
            return fmt.Errorf("read error: %v", err)
        }
        
        // Parse monitor server configurations
        parseMonitorConfig(data)
    }
    
    // Start main update loop
    timer := 0
    for {
        // Collect system metrics
        metricsData, err := collectSystemMetrics()
        if err != nil {
            return fmt.Errorf("failed to collect metrics: %v", err)
        }
        
        // Add network check if needed
        if timer <= 0 {
            online := checkNetworkConnectivity(checkIP)
            if checkIP == 4 {
                metricsData["online4"] = online
            } else if checkIP == 6 {
                metricsData["online6"] = online
            }
            timer = 10
        } else {
            timer -= cfg.Interval
        }
        
        // Add ping statistics
        addPingStats(metricsData)
        
        // Add custom monitor data
        addMonitorData(metricsData)
        
        // Send update to server
        updateJSON, err := json.Marshal(metricsData)
        if err != nil {
            return fmt.Errorf("JSON marshal error: %v", err)
        }
        
        _, err = conn.Write([]byte("update " + string(updateJSON) + "\n"))
        if err != nil {
            return fmt.Errorf("failed to send update: %v", err)
        }
        
        time.Sleep(time.Duration(cfg.Interval) * time.Second)
    }
}

func monitorNetworkSpeed() {
    var prevRx, prevTx int64
    firstRun := true
    
    for {
        file, err := os.Open("/proc/net/dev")
        if err != nil {
            log.Printf("Error reading network data: %v", err)
            time.Sleep(time.Duration(cfg.Interval) * time.Second)
            continue
        }
        
        var currentRx, currentTx int64
        scanner := bufio.NewScanner(file)
        
        // Skip the first two header lines
        scanner.Scan()
        scanner.Scan()
        
        for scanner.Scan() {
            line := scanner.Text()
            parts := strings.Split(line, ":")
            if len(parts) != 2 {
                continue
            }
            
            // Skip interfaces we don't want to include
            ifName := strings.TrimSpace(parts[0])
            if strings.Contains(ifName, "lo") || strings.Contains(ifName, "tun") || 
               strings.Contains(ifName, "docker") || strings.Contains(ifName, "veth") ||
               strings.Contains(ifName, "br-") || strings.Contains(ifName, "vmbr") ||
               strings.Contains(ifName, "vnet") || strings.Contains(ifName, "kube") {
                continue
            }
            
            fields := strings.Fields(parts[1])
            if len(fields) < 10 || fields[0] == "0" || fields[8] == "0" {
                continue
            }
            
            rx, _ := strconv.ParseInt(fields[0], 10, 64)
            tx, _ := strconv.ParseInt(fields[8], 10, 64)
            
            currentRx += rx
            currentTx += tx
        }
        
        file.Close()
        
        if !firstRun {
            networkSpeed.mu.Lock()
            now := float64(time.Now().Unix())
            diff := now - networkSpeed.Clock
            if diff <= 0 {
                diff = 1
            }
            
            networkSpeed.Clock = now
            networkSpeed.Diff = diff
            networkSpeed.NetRx = int((currentRx - prevRx) / int64(diff))
            networkSpeed.NetTx = int((currentTx - prevTx) / int64(diff))
            networkSpeed.AvgRx = currentRx
            networkSpeed.AvgTx = currentTx
            networkSpeed.mu.Unlock()
        }
        
        prevRx = currentRx
        prevTx = currentTx
        firstRun = false
        
        time.Sleep(time.Duration(cfg.Interval) * time.Second)
    }
}

func monitorDiskIO() {
    for {
        // Get list of process directories
        procDirs, err := os.ReadDir("/proc")
        if err != nil {
            log.Printf("Error reading /proc: %v", err)
            time.Sleep(time.Duration(cfg.Interval) * time.Second)
            continue
        }
        
        // First snapshot
        snapshot1 := make(map[string]map[string]int64)
        for _, dir := range procDirs {
            if !dir.IsDir() {
                continue
            }
            
            // Check if the directory name is a number (PID)
            pid := dir.Name()
            if _, err := strconv.Atoi(pid); err != nil {
                continue
            }
            
            // Read process IO stats
            ioData, err := os.ReadFile(fmt.Sprintf("/proc/%s/io", pid))
            if err != nil {
                continue
            }
            
            // Read process name
            cmdData, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", pid))
            if err != nil {
                continue
            }
            
            procName := strings.TrimSpace(string(cmdData))
            if procName == "" {
                continue
            }
            
            // Parse IO data
            var readBytes, writeBytes int64
            scanner := bufio.NewScanner(strings.NewReader(string(ioData)))
            for scanner.Scan() {
                line := scanner.Text()
                if strings.HasPrefix(line, "read_bytes:") {
                    readBytes, _ = strconv.ParseInt(strings.TrimSpace(strings.Split(line, ":")[1]), 10, 64)
                } else if strings.HasPrefix(line, "write_bytes:") && !strings.Contains(line, "cancelled_write_bytes") {
                    writeBytes, _ = strconv.ParseInt(strings.TrimSpace(strings.Split(line, ":")[1]), 10, 64)
                }
            }
            
            snapshot1[pid] = map[string]int64{
                "read": readBytes,
                "write": writeBytes,
                "name": int64(len(procName)), // Store name length for comparison
            }
        }
        
        time.Sleep(time.Duration(cfg.Interval) * time.Second)
        
        // Second snapshot
        var totalRead, totalWrite int64
        for pid, data1 := range snapshot1 {
            // Read process IO stats again
            ioData, err := os.ReadFile(fmt.Sprintf("/proc/%s/io", pid))
            if err != nil {
                continue
            }
            
            // Read process name again
            cmdData, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", pid))
            if err != nil {
                continue
            }
            
            procName := strings.TrimSpace(string(cmdData))
            if int64(len(procName)) != data1["name"] {
                continue // Process name changed, skip
            }
            
            // Parse IO data
            var readBytes, writeBytes int64
            scanner := bufio.NewScanner(strings.NewReader(string(ioData)))
            for scanner.Scan() {
                line := scanner.Text()
                if strings.HasPrefix(line, "read_bytes:") {
                    readBytes, _ = strconv.ParseInt(strings.TrimSpace(strings.Split(line, ":")[1]), 10, 64)
                } else if strings.HasPrefix(line, "write_bytes:") && !strings.Contains(line, "cancelled_write_bytes") {
                    writeBytes, _ = strconv.ParseInt(strings.TrimSpace(strings.Split(line, ":")[1]), 10, 64)
                }
            }
            
            if procName != "bash" { // Skip bash processes as in Python code
                totalRead += readBytes - data1["read"]
                totalWrite += writeBytes - data1["write"]
            }
        }
        
        diskIO.mu.Lock()
        diskIO.Read = totalRead
        diskIO.Write = totalWrite
        diskIO.mu.Unlock()
    }
}

func parseMonitorConfig(data string) {
    monitorMutex.Lock()
    defer monitorMutex.Unlock()
    
    // Clear existing configuration
    for k := range monitorServers {
        delete(monitorServers, k)
    }
    
    lines := strings.Split(data, "\n")
    for _, line := range lines {
        if strings.Contains(line, "monitor") && strings.Contains(line, "type") && strings.Contains(line, "{") && strings.Contains(line, "}") {
            jsonStart := strings.Index(line, "{")
            jsonEnd := strings.LastIndex(line, "}") + 1
            if jsonStart < 0 || jsonEnd <= jsonStart {
                continue
            }
            
            jsonStr := line[jsonStart:jsonEnd]
            var monData map[string]interface{}
            if err := json.Unmarshal([]byte(jsonStr), &monData); err != nil {
                log.Printf("Error parsing monitor config: %v", err)
                continue
            }
            
            name, ok := monData["name"].(string)
            if !ok {
                continue
            }
            
            monitorServers[name] = map[string]interface{}{
                "type":         monData["type"],
                "host":         monData["host"],
                "interval":     monData["interval"],
                "dns_time":     0,
                "connect_time": 0,
                "download_time": 0,
                "online_rate":  1.0,
            }
            
            // Start monitor thread for this server
            hostStr, _ := monData["host"].(string)
            typeStr, _ := monData["type"].(string)
            interval, _ := monData["interval"].(float64)
            
            go monitorServer(name, hostStr, int(interval), typeStr)
        }
    }
}

func monitorServer(name, host string, interval int, monitorType string) {
    // Create a packet queue for this monitor
    packetQueue := network.NewPacketQueue(cfg.OnlinePacketHistoryLen)
    lostPacket := 0
    
    for {
        monitorMutex.Lock()
        if _, exists := monitorServers[name]; !exists {
            monitorMutex.Unlock()
            return
        }
        monitorMutex.Unlock()
        
        var success bool
        
        // Different monitoring based on type
        switch monitorType {
        case "http":
            success = monitorHTTP(name, host, false)
        case "https":
            success = monitorHTTP(name, host, true)
        case "tcp":
            success = monitorTCP(name, host)
        default:
            log.Printf("Unknown monitor type: %s", monitorType)
            success = false
        }
        
        // Update packet queue
        if success {
            packetQueue.Put(true)
        } else {
            lostPacket++
            packetQueue.Put(false)
        }
        
        // Calculate online rate
        if packetQueue.Size() > 5 {
            onlineRate := 1.0 - float64(lostPacket)/float64(packetQueue.Size())
            
            monitorMutex.Lock()
            if server, exists := monitorServers[name]; exists {
                server["online_rate"] = onlineRate
            }
            monitorMutex.Unlock()
        }
        
        time.Sleep(time.Duration(interval) * time.Second)
    }
}

func monitorHTTP(name, host string, isHTTPS bool) bool {
    protocol := "http"
    port := 80
    if isHTTPS {
        protocol = "https"
        port = 443
    }
    
    // Remove protocol prefix
    address := strings.TrimPrefix(host, protocol+"://")
    
    // DNS resolution
    dnsStart := time.Now()
    
    var dnsTarget string
    if cfg.ProbeProtocolPrefer == "ipv4" {
        addrs, err := net.LookupIP(address)
        if err != nil {
            return false
        }
        
        for _, addr := range addrs {
            if ipv4 := addr.To4(); ipv4 != nil {
                dnsTarget = ipv4.String()
                break
            }
        }
    } else {
        addrs, err := net.LookupIP(address)
        if err != nil {
            return false
        }
        
        for _, addr := range addrs {
            if ipv4 := addr.To4(); ipv4 == nil {
                dnsTarget = addr.String()
                break
            }
        }
    }
    
    if dnsTarget == "" {
        return false
    }
    
    dnsTime := time.Since(dnsStart).Milliseconds()
    
    // TCP connection
    connectStart := time.Now()
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dnsTarget, port), 6*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    
    connectTime := time.Since(connectStart).Milliseconds()
    
    // HTTP request
    downloadStart := time.Now()
    var resp []byte
    
    if isHTTPS {
        tlsConn := tls.Client(conn, &tls.Config{
            ServerName:         address,
            InsecureSkipVerify: true,
        })
        defer tlsConn.Close()
        
        if err := tlsConn.Handshake(); err != nil {
            return false
        }
        
        request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ServerStatus/goclient\r\nConnection: close\r\n\r\n", address)
        if _, err := tlsConn.Write([]byte(request)); err != nil {
            return false
        }
        
        buf := make([]byte, 4096)
        for {
            n, err := tlsConn.Read(buf)
            if err != nil {
                if err == io.EOF {
                    break
                }
                return false
            }
            resp = append(resp, buf[:n]...)
        }
    } else {
        request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ServerStatus/goclient\r\nConnection: close\r\n\r\n", address)
        if _, err := conn.Write([]byte(request)); err != nil {
            return false
        }
        
        buf := make([]byte, 4096)
        for {
            n, err := conn.Read(buf)
            if err != nil {
                if err == io.EOF {
                    break
                }
                return false
            }
            resp = append(resp, buf[:n]...)
        }
    }
    
    downloadTime := time.Since(downloadStart).Milliseconds()
    
    // Check HTTP status code
    respStr := string(resp)
    firstLine := strings.Split(respStr, "\r\n")[0]
    parts := strings.Fields(firstLine)
    if len(parts) < 2 {
        return false
    }
    
    statusCode := parts[1]
    validCodes := map[string]bool{"200": true, "204": true, "301": true, "302": true, "401": true}
    if !validCodes[statusCode] {
        return false
    }
    
    // Update times in the monitor data
    monitorMutex.Lock()
    if server, exists := monitorServers[name]; exists {
        server["dns_time"] = int(dnsTime)
        server["connect_time"] = int(connectTime)
        server["download_time"] = int(downloadTime)
    }
    monitorMutex.Unlock()
    
    return true
}

func monitorTCP(name, host string) bool {
    parts := strings.Split(host, ":")
    if len(parts) != 2 {
        return false
    }
    
    hostname := parts[0]
    port, err := strconv.Atoi(parts[1])
    if err != nil {
        return false
    }
    
    // DNS resolution
    dnsStart := time.Now()
    
    var dnsTarget string
    if cfg.ProbeProtocolPrefer == "ipv4" {
        addrs, err := net.LookupIP(hostname)
        if err != nil {
            return false
        }
        
        for _, addr := range addrs {
            if ipv4 := addr.To4(); ipv4 != nil {
                dnsTarget = ipv4.String()
                break
            }
        }
    } else {
        addrs, err := net.LookupIP(hostname)
        if err != nil {
            return false
        }
        
        for _, addr := range addrs {
            if ipv4 := addr.To4(); ipv4 == nil {
                dnsTarget = addr.String()
                break
            }
        }
    }
    
    if dnsTarget == "" {
        return false
    }
    
    dnsTime := time.Since(dnsStart).Milliseconds()
    
    // TCP connection
    connectStart := time.Now()
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dnsTarget, port), 6*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()
    
    connectTime := time.Since(connectStart).Milliseconds()
    
    // Simple data exchange
    downloadStart := time.Now()
    
    if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
        return false
    }
    
    buf := make([]byte, 1024)
    if _, err := conn.Read(buf); err != nil && err != io.EOF {
        return false
    }
    
    downloadTime := time.Since(downloadStart).Milliseconds()
    
    // Update times in the monitor data
    monitorMutex.Lock()
    if server, exists := monitorServers[name]; exists {
        server["dns_time"] = int(dnsTime)
        server["connect_time"] = int(connectTime)
        server["download_time"] = int(downloadTime)
    }
    monitorMutex.Unlock()
    
    return true
}

func collectSystemMetrics() (map[string]interface{}, error) {
    metricsData := make(map[string]interface{})
    
    // Get uptime
    uptime, err := metrics.GetUptime()
    if err != nil {
        return nil, fmt.Errorf("error getting uptime: %v", err)
    }
    metricsData["uptime"] = uptime
    
    // Get load average
    loadavg, err := os.ReadFile("/proc/loadavg")
    if err != nil {
        return nil, fmt.Errorf("error reading load average: %v", err)
    }
    
    loads := strings.Fields(string(loadavg))
    if len(loads) < 3 {
        return nil, fmt.Errorf("invalid load average format")
    }
    
    load1, _ := strconv.ParseFloat(loads[0], 64)
    load5, _ := strconv.ParseFloat(loads[1], 64)
    load15, _ := strconv.ParseFloat(loads[2], 64)
    
    metricsData["load_1"] = load1
    metricsData["load_5"] = load5
    metricsData["load_15"] = load15
    
    // Get memory information
    memTotal, memUsed, swapTotal, swapUsed, err := metrics.GetMemory()
    if err != nil {
        return nil, fmt.Errorf("error getting memory info: %v", err)
    }
    
    metricsData["memory_total"] = memTotal
    metricsData["memory_used"] = memUsed
    metricsData["swap_total"] = swapTotal
    metricsData["swap_used"] = swapUsed
    
    // Get disk usage
    hddTotal, hddUsed, err := metrics.GetHDDUsage()
    if err != nil {
        return nil, fmt.Errorf("error getting disk usage: %v", err)
    }
    
    metricsData["hdd_total"] = hddTotal
    metricsData["hdd_used"] = hddUsed
    
    // Get CPU usage
    cpu, err := metrics.GetCPUUsage(cfg.Interval)
    if err != nil {
        return nil, fmt.Errorf("error getting CPU usage: %v", err)
    }
    
    metricsData["cpu"] = math.Round(cpu*10) / 10
    
    // Get network speeds
    networkSpeed.mu.Lock()
    metricsData["network_rx"] = networkSpeed.NetRx
    metricsData["network_tx"] = networkSpeed.NetTx
    networkSpeed.mu.Unlock()
    
    // Get network traffic
    netIn, netOut, err := metrics.GetNetworkTraffic()
    if err != nil {
        return nil, fmt.Errorf("error getting network traffic: %v", err)
    }
    
    metricsData["network_in"] = netIn
    metricsData["network_out"] = netOut
    
    // Get TCP, UDP, process and thread counts
    tcp, udp, proc, thread, err := metrics.GetTUPD()
    if err != nil {
        return nil, fmt.Errorf("error getting TUPD counts: %v", err)
    }
    
    metricsData["tcp"] = tcp
    metricsData["udp"] = udp
    metricsData["process"] = proc
    metricsData["thread"] = thread
    
    // Get disk I/O
    diskIO.mu.Lock()
    metricsData["io_read"] = diskIO.Read
    metricsData["io_write"] = diskIO.Write
    diskIO.mu.Unlock()
    
    return metricsData, nil
}

func checkNetworkConnectivity(ipVersion int) bool {
    var host string
    
    if ipVersion == 4 {
        host = "ipv4.google.com"
    } else if ipVersion == 6 {
        host = "ipv6.google.com"
    } else {
        return false
    }
    
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), 2*time.Second)
    if err != nil {
        return false
    }
    
    conn.Close()
    return true
}

func addPingStats(metricsData map[string]interface{}) {
    for key, stats := range pingStats {
        stats.Lock()
        metricsData["ping_"+key] = stats.LostRate * 100
        metricsData["time_"+key] = stats.PingTime
        stats.Unlock()
    }
}

func addMonitorData(metricsData map[string]interface{}) {
    monitorMutex.Lock()
    defer monitorMutex.Unlock()
    
    if len(monitorServers) == 0 {
        return
    }
    
    var customData []string
    
    for name, server := range monitorServers {
        dnsTime, _ := server["dns_time"].(int)
        connectTime, _ := server["connect_time"].(int)
        downloadTime, _ := server["download_time"].(int)
        onlineRate, _ := server["online_rate"].(float64)
        
        customData = append(customData, fmt.Sprintf("%s\\t解析: %d\\t连接: %d\\t下载: %d\\t在线率: <code>%.1f%%</code>", 
            name, dnsTime, connectTime, downloadTime, onlineRate*100))
    }
    
    metricsData["custom"] = strings.Join(customData, "<br>")
}