package vpngate

import (
	"testing"
)

const sampleCSV = `*vpn_servers
#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
public-vpn-58,219.100.37.49,2996054,8,340706815,Japan,JP,96,1000405115,16883156,900885718362624,2weeks,Daiyuu Nobori_ Japan. Academic Use Only.,,IyMjIyMjIyM=
public-vpn-218,219.100.37.187,2784880,15,194882755,Japan,JP,52,1000397506,1181046,46126878858739,2weeks,Daiyuu Nobori_ Japan. Academic Use Only.,,IyMjIyMjIyM=
vpn460701713,118.40.9.143,1267762,25,11506689,Korea Republic of,KR,59,1609634132,597965,54283766203785,2weeks,DESKTOP-LT8EBSG's owner,,IyMjIyMjIyM=`

func TestParseVPNServers(t *testing.T) {
	servers, err := ParseCSV(sampleCSV)
	if err != nil {
		t.Fatalf("ParseCSV() error: %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	// Check first server
	s0 := servers[0]
	if s0.HostName != "public-vpn-58" {
		t.Errorf("expected HostName 'public-vpn-58', got %q", s0.HostName)
	}
	if s0.IP != "219.100.37.49" {
		t.Errorf("expected IP '219.100.37.49', got %q", s0.IP)
	}
	if s0.Ping != 8 {
		t.Errorf("expected Ping 8, got %d", s0.Ping)
	}
	if s0.Speed != 340706815 {
		t.Errorf("expected Speed 340706815, got %d", s0.Speed)
	}
	if s0.CountryLong != "Japan" {
		t.Errorf("expected CountryLong 'Japan', got %q", s0.CountryLong)
	}
	if s0.CountryShort != "JP" {
		t.Errorf("expected CountryShort 'JP', got %q", s0.CountryShort)
	}
	if s0.Score != 2996054 {
		t.Errorf("expected Score 2996054, got %d", s0.Score)
	}

	// Check third server (has apostrophe in operator)
	s2 := servers[2]
	if s2.HostName != "vpn460701713" {
		t.Errorf("expected HostName 'vpn460701713', got %q", s2.HostName)
	}
	if s2.CountryLong != "Korea Republic of" {
		t.Errorf("expected CountryLong 'Korea Republic of', got %q", s2.CountryLong)
	}
	if s2.CountryShort != "KR" {
		t.Errorf("expected CountryShort 'KR', got %q", s2.CountryShort)
	}
}

func TestParseCSVEmpty(t *testing.T) {
	servers, err := ParseCSV("*vpn_servers")
	if err != nil {
		t.Fatalf("ParseCSV() error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseCSVInvalidHeader(t *testing.T) {
	_, err := ParseCSV("not-a-valid-header")
	if err == nil {
		t.Fatal("expected error for invalid CSV, got nil")
	}
}

func TestFetchServersFailsOnBadURL(t *testing.T) {
	f := &Fetcher{
		APIURL: "http://127.0.0.1:1/nonexistent",
	}
	_, err := f.FetchServers()
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}