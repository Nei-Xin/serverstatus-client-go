package network

import (
    "fmt"
    "net"
    "strconv"
    "sync"
    "time"
)

// PingStatistics stores ping data
type PingStatistics struct {
    LostRate  float64
    PingTime  int
    mu        sync.Mutex
}

func (s *PingStatistics) Lock() {
    s.mu.Lock()
}

// Unlock unlocks the statistics
func (s *PingStatistics) Unlock() {
    s.mu.Unlock()
}
// PacketQueue is a fixed-size queue for tracking packet history
type PacketQueue struct {
    items      []bool
    size       int
    capacity   int
    lostPacket int
    mu         sync.Mutex
}

// NewPacketQueue creates a new packet queue with specified capacity
func NewPacketQueue(capacity int) *PacketQueue {
    return &PacketQueue{
        items:    make([]bool, 0, capacity),
        capacity: capacity,
    }
}

// Put adds a packet status to the queue
func (q *PacketQueue) Put(received bool) {
    q.mu.Lock()
    defer q.mu.Unlock()
    
    if len(q.items) == q.capacity {
        // Remove oldest item
        if !q.items[0] {
            q.lostPacket--
        }
        q.items = q.items[1:]
    }
    
    q.items = append(q.items, received)
    if !received {
        q.lostPacket++
    }
    q.size = len(q.items)
}

// LostRate returns the current packet loss rate
func (q *PacketQueue) LostRate() float64 {
    q.mu.Lock()
    defer q.mu.Unlock()
    
    if q.size == 0 {
        return 0
    }
    return float64(q.lostPacket) / float64(q.size)
}

// Size returns the current size of the queue
func (q *PacketQueue) Size() int {
    q.mu.Lock()
    defer q.mu.Unlock()
    return q.size
}

// StartPingThread starts a goroutine to ping specified hosts
func StartPingThread(host string, stats *PingStatistics, port int, interval int, preferIPv4 bool) {
    queue := NewPacketQueue(100)
    
    go func() {
        for {
            var ip string
            var err error
            
            // Resolve IP address
            if preferIPv4 {
                ip, err = resolveIPv4(host)
            } else {
                ip, err = resolveIPv6(host)
            }
            
            if err != nil {
                ip = host
            }
            
            // Attempt connection
            start := time.Now()
            conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), time.Second)
            elapsed := time.Since(start).Milliseconds()
            
            if err == nil {
                conn.Close()
                queue.Put(true)
                
                stats.mu.Lock()
                stats.PingTime = int(elapsed)
                stats.LostRate = queue.LostRate()
                stats.mu.Unlock()
            } else {
                queue.Put(false)
                
                stats.mu.Lock()
                stats.LostRate = queue.LostRate()
                stats.mu.Unlock()
            }
            
            time.Sleep(time.Duration(interval) * time.Second)
        }
    }()
}

// Helper functions for IP resolution
func resolveIPv4(host string) (string, error) {
    addrs, err := net.LookupIP(host)
    if err != nil {
        return "", err
    }
    
    for _, addr := range addrs {
        if ipv4 := addr.To4(); ipv4 != nil {
            return ipv4.String(), nil
        }
    }
    
    return "", fmt.Errorf("no IPv4 address found for host: %s", host)
}

func resolveIPv6(host string) (string, error) {
    addrs, err := net.LookupIP(host)
    if err != nil {
        return "", err
    }
    
    for _, addr := range addrs {
        if ipv4 := addr.To4(); ipv4 == nil {
            return addr.String(), nil
        }
    }
    
    return "", fmt.Errorf("no IPv6 address found for host: %s", host)
}