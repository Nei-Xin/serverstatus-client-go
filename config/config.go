package config

// Configuration holds all server client settings
type Configuration struct {
    Server               string
    User                 string
    Password             string
    Port                 int
    CU                   string
    CT                   string
    CM                   string
    ProbePort            int
    ProbeProtocolPrefer  string
    PingPacketHistoryLen int
    OnlinePacketHistoryLen int
    Interval             int
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Configuration {
    return &Configuration{
        Server:               "127.0.0.1",
        User:                 "s01",
        Password:             "USER_DEFAULT_PASSWORD",
        Port:                 35601,
        CU:                   "cu.tz.zzii.de",
        CT:                   "ct.tz.zzii.de",
        CM:                   "cm.tz.zzii.de",
        ProbePort:            80,
        ProbeProtocolPrefer:  "ipv4",
        PingPacketHistoryLen: 100,
        OnlinePacketHistoryLen: 72,
        Interval:             1,
    }
}