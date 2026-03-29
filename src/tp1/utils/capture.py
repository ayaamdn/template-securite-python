from collections import defaultdict
from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, DNS, Raw
from src.tp1.utils.lib import choose_interface


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.protocol_counts = defaultdict(int)
        self.alerts = []

    def capture_traffic(self, count: int = 100, timeout: int = 30) -> None:
        print(f"Capture du trafic sur l'interface : {self.interface}")
        print(f"Nombre de paquets max : {count} | Timeout : {timeout}s\n")

        self.packets = sniff(
            iface=self.interface,
            count=count,
            timeout=timeout
        )
        print(f"[+] {len(self.packets)} paquets capturés.")

    def get_all_protocols(self) -> dict:
        self.protocol_counts = defaultdict(int)

        for packet in self.packets:
            if packet.haslayer(ARP):
                self.protocol_counts["ARP"] += 1
            elif packet.haslayer(DNS):
                self.protocol_counts["DNS"] += 1
            elif packet.haslayer(TCP):
                self.protocol_counts["TCP"] += 1
            elif packet.haslayer(UDP):
                self.protocol_counts["UDP"] += 1
            elif packet.haslayer(ICMP):
                self.protocol_counts["ICMP"] += 1
            elif packet.haslayer(IP):
                self.protocol_counts["IP"] += 1
            else:
                self.protocol_counts["Autre"] += 1

        return dict(self.protocol_counts)

    def sort_network_protocols(self) -> dict:
        sorted_protocols = dict(
            sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)
        )
        return sorted_protocols

    def _detect_sql_injection(self, payload: str) -> bool:
        sql_patterns = [
            "select ", "union ", "insert ", "drop ", "delete ",
            "update ", "' or ", "' and ", "--", "/*", "*/",
            "xp_", "exec(", "execute(", "1=1", "or 1=1"
        ]
        payload_lower = payload.lower()
        return any(pattern in payload_lower for pattern in sql_patterns)

    def _detect_arp_spoofing(self) -> list:
        ip_mac_map = {}
        suspicious = []

        for packet in self.packets:
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc

                if ip in ip_mac_map and ip_mac_map[ip] != mac:
                    suspicious.append({
                        "type": "ARP Spoofing",
                        "protocol": "ARP",
                        "ip": ip,
                        "mac": mac,
                        "detail": f"Conflit MAC pour IP {ip} : {ip_mac_map[ip]} → {mac}"
                    })
                else:
                    ip_mac_map[ip] = mac

        return suspicious

    def analyse(self, protocols: str) -> None:
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        self.alerts = []

        print("Analyse du trafic en cours...\n")

        arp_alerts = self._detect_arp_spoofing()
        self.alerts.extend(arp_alerts)

        for packet in self.packets:
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    if self._detect_sql_injection(payload):
                        ip_src = packet[IP].src if packet.haslayer(IP) else "Inconnue"
                        mac_src = packet.src if hasattr(packet, "src") else "Inconnue"
                        self.alerts.append({
                            "type": "Injection SQL",
                            "protocol": "TCP",
                            "ip": ip_src,
                            "mac": mac_src,
                            "detail": f"Payload suspect détecté depuis {ip_src}"
                        })
                except Exception:
                    pass

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        summary = ""

        if not self.alerts:
            summary += "Aucune activité suspecte détectée. Le trafic semble légitime.\n"
        else:
            summary += f"{len(self.alerts)} tentative(s) d'attaque détectée(s) :\n\n"
            for i, alert in enumerate(self.alerts, 1):
                summary += f"  [{i}] Type     : {alert['type']}\n"
                summary += f"       Protocole : {alert['protocol']}\n"
                summary += f"       IP source : {alert['ip']}\n"
                summary += f"       MAC source: {alert['mac']}\n"
                summary += f"       Détail    : {alert['detail']}\n\n"

        return summary