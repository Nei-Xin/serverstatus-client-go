package metrics

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "os"
    "os/exec"  // 需要这个包用于执行命令
    "regexp"
    "strconv"
    "strings"
    "time"    // 需要这个包用于时间计算
)

// SystemMetrics holds all collected system metrics
type SystemMetrics struct {
    Uptime      int
    Load1       float64
    Load5       float64
    Load15      float64
    MemoryTotal int
    MemoryUsed  int
    SwapTotal   int
    SwapUsed    int
    HDDTotal    int
    HDDUsed     int
    CPU         float64
    NetworkRx   int
    NetworkTx   int
    NetworkIn   int64
    NetworkOut  int64
    TCPCount    int
    UDPCount    int
    ProcessCount int
    ThreadCount  int
    IORead      int64
    IOWrite     int64
}

// GetUptime returns system uptime in seconds
func GetUptime() (int, error) {
    content, err := ioutil.ReadFile("/proc/uptime")
    if err != nil {
        return 0, err
    }
    
    fields := strings.Fields(string(content))
    if len(fields) < 1 {
        return 0, fmt.Errorf("invalid uptime format")
    }
    
    secs, err := strconv.ParseFloat(fields[0], 64)
    if err != nil {
        return 0, err
    }
    
    return int(secs), nil
}

// GetMemory returns memory information
func GetMemory() (int, int, int, int, error) {
    file, err := os.Open("/proc/meminfo")
    if err != nil {
        return 0, 0, 0, 0, err
    }
    defer file.Close()
    
    var memTotal, memFree, buffers, cached, sReclaimable, swapTotal, swapFree int64
    
    scanner := bufio.NewScanner(file)
    reParser := regexp.MustCompile(`^(\S+):\s+(\d+)\s+kB`)
    
    for scanner.Scan() {
        line := scanner.Text()
        matches := reParser.FindStringSubmatch(line)
        if len(matches) != 3 {
            continue
        }
        
        key := matches[1]
        value, _ := strconv.ParseInt(matches[2], 10, 64)
        
        switch key {
        case "MemTotal":
            memTotal = value
        case "MemFree":
            memFree = value
        case "Buffers":
            buffers = value
        case "Cached":
            cached = value
        case "SReclaimable":
            sReclaimable = value
        case "SwapTotal":
            swapTotal = value
        case "SwapFree":
            swapFree = value
        }
    }
    
    if err := scanner.Err(); err != nil {
        return 0, 0, 0, 0, err
    }
    
    memUsed := memTotal - memFree - buffers - cached - sReclaimable
    
    return int(memTotal), int(memUsed), int(swapTotal), int(swapTotal - swapFree), nil
}

// GetHDDUsage returns disk usage information
func GetHDDUsage() (int, int, error) {
    cmd := exec.Command("df", "-Tlm", "--total", "-t", "ext4", "-t", "ext3", "-t", "ext2", "-t", "reiserfs", 
                      "-t", "jfs", "-t", "ntfs", "-t", "fat32", "-t", "btrfs", "-t", "fuseblk", "-t", "zfs", 
                      "-t", "simfs", "-t", "xfs")
    
    output, err := cmd.Output()
    if err != nil {
        return 0, 0, err
    }
    
    lines := strings.Split(string(output), "\n")
    if len(lines) < 2 {
        return 0, 0, fmt.Errorf("unexpected df output format")
    }
    
    // Get the last line (total)
    totalLine := lines[len(lines)-2] // -2 because the last line is empty
    fields := strings.Fields(totalLine)
    
    if len(fields) < 3 {
        return 0, 0, fmt.Errorf("unexpected df total line format")
    }
    
    size, err := strconv.Atoi(fields[2])
    if err != nil {
        return 0, 0, err
    }
    
    used, err := strconv.Atoi(fields[3])
    if err != nil {
        return 0, 0, err
    }
    
    return size, used, nil
}

// GetCPUUsage returns CPU usage percentage
func GetCPUUsage(interval int) (float64, error) {
    // First reading
    stat1, err := os.ReadFile("/proc/stat")
    if err != nil {
        return 0, err
    }
    
    time1 := parseCPUTime(string(stat1))
    
    time.Sleep(time.Duration(interval) * time.Second)
    
    // Second reading
    stat2, err := os.ReadFile("/proc/stat")
    if err != nil {
        return 0, err
    }
    
    time2 := parseCPUTime(string(stat2))
    
    // Calculate deltas
    var timeUsed int64
    var timeTotal int64
    
    for i := 0; i < 3; i++ {
        timeUsed += time2[i] - time1[i]
    }
    
    for i := 0; i < 4; i++ {
        timeTotal += time2[i] - time1[i]
    }
    
    if timeTotal == 0 {
        timeTotal = 1
    }
    
    cpuUsage := 100.0 * float64(timeUsed) / float64(timeTotal)
    return cpuUsage, nil
}

// ParseCPUTime parses CPU time from /proc/stat
func parseCPUTime(statContent string) []int64 {
    lines := strings.Split(statContent, "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "cpu ") {
            fields := strings.Fields(line)[1:] // Skip "cpu" field
            result := make([]int64, 4)
            
            for i := 0; i < 4 && i < len(fields); i++ {
                result[i], _ = strconv.ParseInt(fields[i], 10, 64)
            }
            
            return result
        }
    }
    
    return make([]int64, 4)
}

// GetNetworkTraffic returns total network in/out bytes
func GetNetworkTraffic() (int64, int64, error) {
    file, err := os.Open("/proc/net/dev")
    if err != nil {
        return 0, 0, err
    }
    defer file.Close()
    
    var netIn, netOut int64
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
        
        in, _ := strconv.ParseInt(fields[0], 10, 64)
        out, _ := strconv.ParseInt(fields[8], 10, 64)
        
        netIn += in
        netOut += out
    }
    
    return netIn, netOut, nil
}

// GetTUPD returns TCP, UDP, Process and Thread counts
func GetTUPD() (int, int, int, int, error) {
    // TCP connections
    tcpCmd := exec.Command("sh", "-c", "ss -t | wc -l")
    tcpOut, err := tcpCmd.Output()
    if err != nil {
        return 0, 0, 0, 0, err
    }
    
    tcpCount, _ := strconv.Atoi(strings.TrimSpace(string(tcpOut)))
    tcpCount-- // Subtract header line
    
    // UDP connections
    udpCmd := exec.Command("sh", "-c", "ss -u | wc -l")
    udpOut, err := udpCmd.Output()
    if err != nil {
        return 0, 0, 0, 0, err
    }
    
    udpCount, _ := strconv.Atoi(strings.TrimSpace(string(udpOut)))
    udpCount-- // Subtract header line
    
    // Process count
    procCmd := exec.Command("sh", "-c", "ps -ef | wc -l")
    procOut, err := procCmd.Output()
    if err != nil {
        return 0, 0, 0, 0, err
    }
    
    procCount, _ := strconv.Atoi(strings.TrimSpace(string(procOut)))
    procCount -= 2 // Subtract header lines
    
    // Thread count
    threadCmd := exec.Command("sh", "-c", "ps -eLf | wc -l")
    threadOut, err := threadCmd.Output()
    if err != nil {
        return 0, 0, 0, 0, err
    }
    
    threadCount, _ := strconv.Atoi(strings.TrimSpace(string(threadOut)))
    threadCount -= 2 // Subtract header lines
    
    return tcpCount, udpCount, procCount, threadCount, nil
}