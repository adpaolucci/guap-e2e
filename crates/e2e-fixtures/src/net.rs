use std::path::Path;
use anyhow::{ensure, Result};
use crate::util::{read_u16_be, read_u16_le, read_u32_le, write_file_deterministic, FIXED_UNIX_SECS};

fn rfc1071_sum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8, payload_len: usize, id: u16) -> [u8; 20] {
    let total_len = (20 + payload_len) as u16;
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45;
    hdr[1] = 0x00;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&id.to_be_bytes());
    hdr[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    hdr[8] = 64;
    hdr[9] = proto;
    hdr[12..16].copy_from_slice(&src);
    hdr[16..20].copy_from_slice(&dst);
    let ck = rfc1071_sum(&hdr, 0);
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
    hdr
}

fn pseudo_init(src: [u8; 4], dst: [u8; 4], proto: u8, l4_len: u16) -> u32 {
    let mut sum = 0u32;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += proto as u32;
    sum += l4_len as u32;
    sum
}

#[allow(clippy::too_many_arguments)]
fn eth_ipv4_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ip_id: u16,
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(payload);
    let mut ck = rfc1071_sum(&udp, pseudo_init(src_ip, dst_ip, 17, udp_len));
    if ck == 0 {
        ck = 0xFFFF;
    }
    udp[6..8].copy_from_slice(&ck.to_be_bytes());

    let ip = ipv4_header(src_ip, dst_ip, 17, udp.len(), ip_id);
    let mut frame = Vec::with_capacity(14 + 20 + udp.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

#[allow(clippy::too_many_arguments)]
fn eth_ipv4_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    ip_id: u16,
) -> Vec<u8> {
    let tcp_len = (20 + payload.len()) as u16;
    let mut tcp = Vec::with_capacity(tcp_len as usize);
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50); // data offset = 5 (20 bytes)
    tcp.push(flags);
    tcp.extend_from_slice(&65535u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
    tcp.extend_from_slice(payload);
    let ck = rfc1071_sum(&tcp, pseudo_init(src_ip, dst_ip, 6, tcp_len));
    tcp[16..18].copy_from_slice(&ck.to_be_bytes());

    let ip = ipv4_header(src_ip, dst_ip, 6, tcp.len(), ip_id);
    let mut frame = Vec::with_capacity(14 + 20 + tcp.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

fn eth_arp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    op: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&0x0806u16.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    f.push(6);
    f.push(4);
    f.extend_from_slice(&op.to_be_bytes());
    f.extend_from_slice(&sha);
    f.extend_from_slice(&spa);
    f.extend_from_slice(&tha);
    f.extend_from_slice(&tpa);
    f
}

fn bootp_dhcp(op: u8, yiaddr: [u8; 4], client_mac: [u8; 6], opts: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = op;
    b[1] = 1; // Ethernet
    b[2] = 6;
    b[4..8].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    b[16..20].copy_from_slice(&yiaddr);
    b[28..34].copy_from_slice(&client_mac);
    b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // DHCP magic
    b.extend_from_slice(opts);
    b.push(255); // End option
    b
}

fn write_pcap(linktype: u32, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&linktype.to_le_bytes());

    for (ts_sec, ts_usec, data) in packets {
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_usec.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

pub fn build_ethernet_pcap() -> Vec<u8> {
    let mac_cli = [0x02, 0x00, 0x00, 0x00, 0x00, 0x10];
    let mac_gw = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let mac_bcast = [0xFF; 6];
    let mac_mdns = [0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB];
    let ip_cli = [192, 168, 10, 50];
    let ip_gw = [192, 168, 10, 1];
    let ip_web = [93, 184, 216, 34];

    let t0 = FIXED_UNIX_SECS as u32;
    let mut pkts = Vec::new();

    // 1. ARP Request
    pkts.push((t0, 0, eth_arp(mac_cli, mac_bcast, 1, mac_cli, ip_cli, [0; 6], ip_gw)));
    // 2. ARP Reply
    pkts.push((t0, 1000, eth_arp(mac_gw, mac_cli, 2, mac_gw, ip_gw, mac_cli, ip_cli)));

    // 3..6 DHCP Discover, Offer, Request, Ack
    let d_disc = bootp_dhcp(1, [0; 4], mac_cli, &[53, 1, 1, 12, 9, b'g', b'u', b'a', b'p', b'-', b'h', b'o', b's', b't']);
    pkts.push((t0 + 1, 0, eth_ipv4_udp(mac_cli, mac_bcast, [0; 4], [255; 4], 68, 67, &d_disc, 1)));

    let d_offer = bootp_dhcp(2, ip_cli, mac_cli, &[
        53, 1, 2,
        1, 4, 255, 255, 255, 0,
        3, 4, 192, 168, 10, 1,
        6, 4, 192, 168, 10, 1,
        51, 4, 0, 1, 0x51, 0x80,
        54, 4, 192, 168, 10, 1,
    ]);
    pkts.push((t0 + 1, 2000, eth_ipv4_udp(mac_gw, mac_bcast, ip_gw, [255; 4], 67, 68, &d_offer, 2)));

    let d_req = bootp_dhcp(1, [0; 4], mac_cli, &[
        53, 1, 3,
        50, 4, 192, 168, 10, 50,
        54, 4, 192, 168, 10, 1,
        12, 9, b'g', b'u', b'a', b'p', b'-', b'h', b'o', b's', b't',
    ]);
    pkts.push((t0 + 1, 3000, eth_ipv4_udp(mac_cli, mac_bcast, [0; 4], [255; 4], 68, 67, &d_req, 3)));

    let d_ack = bootp_dhcp(2, ip_cli, mac_cli, &[
        53, 1, 5,
        51, 4, 0, 1, 0x51, 0x80,
        1, 4, 255, 255, 255, 0,
        3, 4, 192, 168, 10, 1,
        6, 4, 192, 168, 10, 1,
        54, 4, 192, 168, 10, 1,
    ]);
    pkts.push((t0 + 1, 4000, eth_ipv4_udp(mac_gw, mac_bcast, ip_gw, [255; 4], 67, 68, &d_ack, 4)));

    // 7. DNS Query (docs.example.org A)
    let mut dns_q = Vec::new();
    dns_q.extend_from_slice(&0x1337u16.to_be_bytes());
    dns_q.extend_from_slice(&0x0100u16.to_be_bytes());
    dns_q.extend_from_slice(&1u16.to_be_bytes());
    dns_q.extend_from_slice(&[0u8; 6]);
    dns_q.extend_from_slice(b"\x04docs\x07example\x03org\x00");
    dns_q.extend_from_slice(&1u16.to_be_bytes());
    dns_q.extend_from_slice(&1u16.to_be_bytes());
    pkts.push((t0 + 2, 0, eth_ipv4_udp(mac_cli, mac_gw, ip_cli, ip_gw, 54321, 53, &dns_q, 5)));

    // 8. DNS Response
    let mut dns_r = Vec::new();
    dns_r.extend_from_slice(&0x1337u16.to_be_bytes());
    dns_r.extend_from_slice(&0x8180u16.to_be_bytes());
    dns_r.extend_from_slice(&1u16.to_be_bytes());
    dns_r.extend_from_slice(&1u16.to_be_bytes());
    dns_r.extend_from_slice(&[0u8; 4]);
    dns_r.extend_from_slice(b"\x04docs\x07example\x03org\x00");
    dns_r.extend_from_slice(&1u16.to_be_bytes());
    dns_r.extend_from_slice(&1u16.to_be_bytes());
    dns_r.extend_from_slice(&0xC00Cu16.to_be_bytes());
    dns_r.extend_from_slice(&1u16.to_be_bytes());
    dns_r.extend_from_slice(&1u16.to_be_bytes());
    dns_r.extend_from_slice(&300u32.to_be_bytes());
    dns_r.extend_from_slice(&4u16.to_be_bytes());
    dns_r.extend_from_slice(&ip_web);
    pkts.push((t0 + 2, 5000, eth_ipv4_udp(mac_gw, mac_cli, ip_gw, ip_cli, 53, 54321, &dns_r, 6)));

    // 9. mDNS Announcement
    let mut mdns = Vec::new();
    mdns.extend_from_slice(&0u16.to_be_bytes());
    mdns.extend_from_slice(&0x8400u16.to_be_bytes());
    mdns.extend_from_slice(&0u16.to_be_bytes());
    mdns.extend_from_slice(&1u16.to_be_bytes());
    mdns.extend_from_slice(&[0u8; 4]);
    mdns.extend_from_slice(b"\x09guap-host\x05local\x00");
    mdns.extend_from_slice(&1u16.to_be_bytes());
    mdns.extend_from_slice(&0x8001u16.to_be_bytes());
    mdns.extend_from_slice(&120u32.to_be_bytes());
    mdns.extend_from_slice(&4u16.to_be_bytes());
    mdns.extend_from_slice(&ip_cli);
    pkts.push((t0 + 3, 0, eth_ipv4_udp(mac_cli, mac_mdns, ip_cli, [224, 0, 0, 251], 5353, 5353, &mdns, 7)));

    // 10. TCP SYN + 11. TCP SYN-ACK (15ms delta)
    pkts.push((t0 + 4, 0, eth_ipv4_tcp(mac_cli, mac_gw, ip_cli, ip_web, 55000, 80, 1000, 0, 0x02, &[], 8)));
    pkts.push((t0 + 4, 15_000, eth_ipv4_tcp(mac_gw, mac_cli, ip_web, ip_cli, 80, 55000, 2000, 1001, 0x12, &[], 9)));

    // 12. HTTP/1.1 Request (NO credentials)
    let http_req = b"GET /index.html HTTP/1.1\r\nHost: docs.example.org\r\nUser-Agent: GuapTestClient/1.0\r\nAccept: text/html\r\n\r\n";
    pkts.push((t0 + 4, 16_000, eth_ipv4_tcp(mac_cli, mac_gw, ip_cli, ip_web, 55000, 80, 1001, 2001, 0x18, http_req, 10)));

    // 13. HTTP/1.1 Response
    let http_resp = b"HTTP/1.1 200 OK\r\nServer: guap-http/1.0\r\nContent-Type: text/html\r\nContent-Length: 29\r\nSet-Cookie: ui_theme=dark; Path=/; HttpOnly; SameSite=Lax\r\n\r\n<html><body>OK!</body></html>";
    pkts.push((t0 + 4, 30_000, eth_ipv4_tcp(mac_gw, mac_cli, ip_web, ip_cli, 80, 55000, 2001, 1001 + http_req.len() as u32, 0x18, http_resp, 11)));

    write_pcap(1, &pkts)
}

pub fn build_wifi_80211_pcap() -> Vec<u8> {
    let mut beacon = Vec::new();
    // 24B 802.11 MAC Header
    beacon.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // Mgmt/Beacon + Dur
    beacon.extend_from_slice(&[0xFF; 6]); // Addr1
    beacon.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]); // Addr2
    beacon.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]); // Addr3
    beacon.extend_from_slice(&[0x10, 0x00]); // SeqCtrl
    // 12B Fixed Params
    beacon.extend_from_slice(&1_000_000u64.to_le_bytes());
    beacon.extend_from_slice(&0x0064u16.to_le_bytes());
    beacon.extend_from_slice(&0x0411u16.to_le_bytes());
    // IEs
    let ssid = b"GUAP-Lab-5G";
    beacon.push(0x00);
    beacon.push(ssid.len() as u8);
    beacon.extend_from_slice(ssid);
    beacon.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
    beacon.extend_from_slice(&[0x03, 0x01, 0x06]);
    beacon.extend_from_slice(&[
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01,
        0x00, 0x00, 0x0F, 0xAC, 0x02, 0x0C, 0x00,
    ]);
    write_pcap(105, &[(FIXED_UNIX_SECS as u32, 0, beacon)])
}

pub fn generate_net_dir(net_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(net_dir)?;

    write_file_deterministic(&net_dir.join("capture_ethernet.pcap"), &build_ethernet_pcap())?;
    write_file_deterministic(&net_dir.join("capture_wifi_80211.pcap"), &build_wifi_80211_pcap())?;

    let mock = serde_json::json!({
        "schema_version": 1,
        "wlan_interfaces": [{
            "interface_guid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "interface_name": "Wi-Fi",
            "description": "GUAP Virtual 802.11ax Adapter",
            "state": "Connected",
            "ssid": "GUAP-Lab-5G",
            "bssid": "AA:BB:CC:11:22:33",
            "phy_type": "802.11ax",
            "channel": 6,
            "frequency_mhz": 2437,
            "rssi_dbm": -48,
            "signal_pct": 92,
            "rx_rate_mbps": 860,
            "tx_rate_mbps": 860,
            "auth_algo": "RSNA_PSK",
            "cipher_algo": "CCMP"
        }],
        "ble_advertisements": [{
            "address": "DE:AD:BE:EF:12:34",
            "address_type": "Random",
            "local_name": "GUAP-Beacon-01",
            "rssi_dbm": -61,
            "tx_power_dbm": 4,
            "advertisement_type": "ConnectableUndirected",
            "service_uuids": ["0000180f-0000-1000-8000-00805f9b34fb"],
            "manufacturer_data_hex": "004c0215",
            "last_seen": "2026-11-22T14:30:00Z"
        }]
    });
    write_file_deterministic(
        &net_dir.join("wlan_ble_mock.json"),
        serde_json::to_string_pretty(&mock)?.as_bytes(),
    )?;

    Ok(())
}

pub fn verify_net_dir(net_dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut details = Vec::new();

    // 1. capture_ethernet.pcap
    let eth_pcap = std::fs::read(net_dir.join("capture_ethernet.pcap"))?;
    ensure!(read_u32_le(&eth_pcap, 0)? == 0xA1B2_C3D4, "bad PCAP magic");
    ensure!(read_u16_le(&eth_pcap, 4)? == 2 && read_u16_le(&eth_pcap, 6)? == 4, "bad PCAP version");
    ensure!(read_u32_le(&eth_pcap, 20)? == 1, "expected LINKTYPE_ETHERNET=1");

    let mut off = 24usize;
    let mut pkt_count = 0usize;
    while off < eth_pcap.len() {
        ensure!(off + 16 <= eth_pcap.len(), "truncated PCAP packet header");
        let incl_len = read_u32_le(&eth_pcap, off + 8)? as usize;
        off += 16;
        ensure!(off + incl_len <= eth_pcap.len(), "truncated PCAP packet body");
        let frame = &eth_pcap[off..off + incl_len];
        let ethertype = read_u16_be(frame, 12)?;
        if ethertype == 0x0800 {
            let ip = &frame[14..34];
            ensure!(rfc1071_sum(ip, 0) == 0, "IPv4 checksum failed on packet {}", pkt_count);
            let proto = ip[9];
            let src_ip: [u8; 4] = ip[12..16].try_into()?;
            let dst_ip: [u8; 4] = ip[16..20].try_into()?;
            let l4 = &frame[34..];
            if proto == 17 || proto == 6 {
                let sum = rfc1071_sum(l4, pseudo_init(src_ip, dst_ip, proto, l4.len() as u16));
                ensure!(sum == 0, "L4 checksum failed on packet {} proto {}", pkt_count, proto);
            }
        }
        off += incl_len;
        pkt_count += 1;
    }
    ensure!(pkt_count >= 12, "expected >= 12 packets, got {}", pkt_count);
    details.push(format!("net/capture_ethernet.pcap: {} packets (IPv4+L4 checksums OK)", pkt_count));

    // 2. capture_wifi_80211.pcap
    let wifi_pcap = std::fs::read(net_dir.join("capture_wifi_80211.pcap"))?;
    ensure!(read_u32_le(&wifi_pcap, 0)? == 0xA1B2_C3D4 && read_u32_le(&wifi_pcap, 20)? == 105, "bad 802.11 PCAP");
    let w_str = String::from_utf8_lossy(&wifi_pcap);
    ensure!(w_str.contains("GUAP-Lab-5G"), "802.11 beacon missing SSID");
    details.push("net/capture_wifi_80211.pcap: LINKTYPE_IEEE802_11 beacon verified".into());

    // 3. wlan_ble_mock.json
    let mock: serde_json::Value = serde_json::from_slice(&std::fs::read(net_dir.join("wlan_ble_mock.json"))?)?;
    ensure!(mock["wlan_interfaces"][0]["ssid"] == "GUAP-Lab-5G", "bad wlan_ble_mock.json");
    details.push("net/wlan_ble_mock.json: verified".into());

    Ok((3, details))
}