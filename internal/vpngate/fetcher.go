package vpngate

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIURL is the VPN Gate iPhone API endpoint.
const DefaultAPIURL = "https://www.vpngate.net/api/iphone/"

// VPNServer represents a single VPN Gate server entry.
type VPNServer struct {
	HostName     string `json:"hostname"`
	IP           string `json:"ip"`
	Score        int    `json:"score"`
	Ping         int    `json:"ping"`
	Speed        int64  `json:"speed"`
	CountryLong  string `json:"country_long"`
	CountryShort string `json:"country_short"`
	NumSessions  int    `json:"num_sessions"`
	Uptime       int64  `json:"uptime"`
	TotalUsers   int64  `json:"total_users"`
	TotalTraffic int64  `json:"total_traffic"`
	LogType      string `json:"log_type"`
	Operator     string `json:"operator"`
	Message      string `json:"message"`
}

// Fetcher fetches VPN Gate server lists.
type Fetcher struct {
	APIURL string
	Client *http.Client
}

// FetchServers retrieves the VPN Gate server list from the API.
func (f *Fetcher) FetchServers() ([]VPNServer, error) {
	if f.APIURL == "" {
		f.APIURL = DefaultAPIURL
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Get(f.APIURL)
	if err != nil {
		return nil, fmt.Errorf("vpngate: fetch failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vpngate: read body failed: %w", err)
	}
	return ParseCSV(string(body))
}

// ParseCSV parses VPN Gate CSV response into VPNServer slice.
func ParseCSV(data string) ([]VPNServer, error) {
	// Normalize line endings
	data = strings.ReplaceAll(data, "\r\n", "\n")
	lines := strings.Split(data, "\n")

	// First line must be "*vpn_servers"
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "*vpn_servers" {
		return nil, fmt.Errorf("vpngate: invalid CSV: missing '*vpn_servers' header")
	}

	// Skip comment lines and find the header line
	var headerIdx int
	for i := 1; i < len(lines); i++ {
		if len(lines[i]) > 0 && lines[i][0] == '#' {
			headerIdx = i
			break
		}
	}
	if headerIdx == 0 {
		// No header line, no data
		return []VPNServer{}, nil
	}

	// Find all data lines (skip header, skip blank, skip comments)
	var dataLines []string
	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '*' || line[0] == '#' {
			continue
		}
		dataLines = append(dataLines, line)
	}

	// Parse as CSV records
	reader := csv.NewReader(strings.NewReader(strings.Join(dataLines, "\n")))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // variable number of fields
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("vpngate: CSV parse error: %w", err)
	}

	servers := make([]VPNServer, 0, len(records))
	for _, rec := range records {
		if len(rec) < 11 {
			continue // malformed row
		}
		s := VPNServer{
			HostName: rec[0],
			IP:       rec[1],
		}
		s.Score, _ = strconv.Atoi(rec[2])
		s.Ping, _ = strconv.Atoi(rec[3])
		s.Speed, _ = strconv.ParseInt(rec[4], 10, 64)
		s.CountryLong = rec[5]
		s.CountryShort = rec[6]
		s.NumSessions, _ = strconv.Atoi(rec[7])
		s.Uptime, _ = strconv.ParseInt(rec[8], 10, 64)
		s.TotalUsers, _ = strconv.ParseInt(rec[9], 10, 64)
		s.TotalTraffic, _ = strconv.ParseInt(rec[10], 10, 64)
		if len(rec) > 11 {
			s.LogType = rec[11]
		}
		if len(rec) > 12 {
			s.Operator = rec[12]
		}
		if len(rec) > 13 {
			s.Message = rec[13]
		}
		servers = append(servers, s)
	}
	return servers, nil
}
