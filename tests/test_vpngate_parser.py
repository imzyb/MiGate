from base64 import b64encode

from migate.vpngate.parser import parse_vpngate_csv


def test_parse_vpngate_csv_decodes_openvpn_config():
    ovpn = "client\ndev tun\nremote 1.2.3.4 1194 udp\n"
    encoded = b64encode(ovpn.encode()).decode()
    csv_text = (
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,"
        "NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,"
        "Message,OpenVPN_ConfigData_Base64\n"
    )
    csv_text += f"vpn.example,1.2.3.4,123,45,999,Japan,JP,1,1000,10,1000,2,op,msg,{encoded}\n"
    csv_text += "*\n"

    nodes = parse_vpngate_csv(csv_text)

    assert len(nodes) == 1
    assert nodes[0].hostname == "vpn.example"
    assert nodes[0].ip == "1.2.3.4"
    assert nodes[0].country == "Japan"
    assert nodes[0].country_code == "JP"
    assert nodes[0].ping_ms == 45
    assert nodes[0].speed == 999
    assert "remote 1.2.3.4" in nodes[0].ovpn_config


def test_parse_vpngate_csv_skips_invalid_base64_rows():
    csv_text = (
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,"
        "NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,"
        "Message,OpenVPN_ConfigData_Base64\n"
    )
    csv_text += "broken.example,1.2.3.4,123,45,999,Japan,JP,1,1000,10,1000,2,op,msg,not-base64!!!\n"
    csv_text += "*\n"

    assert parse_vpngate_csv(csv_text) == []
