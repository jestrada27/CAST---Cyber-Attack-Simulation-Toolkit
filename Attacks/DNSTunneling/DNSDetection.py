#!/usr/bin/env python3
"""
Heuristic DNS tunneling detector (PCAP-based).

What it flags (per source IP + registered-ish domain):
- High average query length / label length
- High Shannon entropy in subdomains (base32/base64-like)
- High unique-subdomain ratio (many one-off names)
- High NXDOMAIN rate
- Lots of TXT queries

Usage:
  python detect_dns_tunnel.py --pcap traffic.pcap
  python detect_dns_tunnel.py --pcap traffic.pcap --min-queries 80 --top 20
"""

import argparse
import math
import re
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

from scapy.all import PcapReader
from scapy.layers.dns import DNS, DNSQR


BASE32_64_CHARS = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c, k in counts.items():
        p = k / n
        ent -= p * math.log2(p)
    return ent


def split_labels(qname: str) -> List[str]:
    qname = qname.strip(".")
    if not qname:
        return []
    return qname.split(".")


def guess_root_domain(qname: str) -> str:
    """
    Lightweight 'root domain' heuristic: last two labels.
    Not a full Public Suffix List implementation, but good enough for alert grouping.
    """
    labels = split_labels(qname)
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return qname.strip(".")


@dataclass
class Stats:
    queries: int = 0
    txt_queries: int = 0
    nxdomain: int = 0
    total_qname_len: int = 0
    max_qname_len: int = 0
    total_max_label_len: int = 0
    max_label_len: int = 0
    total_sub_entropy: float = 0.0
    sub_entropy_samples: int = 0
    unique_qnames: set = field(default_factory=set)
    unique_subdomains: set = field(default_factory=set)

    def add_query(self, qname: str, qtype: int):
        self.queries += 1
        self.unique_qnames.add(qname)

        qlen = len(qname)
        self.total_qname_len += qlen
        self.max_qname_len = max(self.max_qname_len, qlen)

        labels = split_labels(qname)
        if labels:
            ml = max(len(l) for l in labels)
            self.total_max_label_len += ml
            self.max_label_len = max(self.max_label_len, ml)

        # subdomain = everything except last two labels (heuristic)
        if len(labels) > 2:
            sub = ".".join(labels[:-2])
            self.unique_subdomains.add(sub)

            # entropy on subdomain, remove dots for scoring
            sub_compact = sub.replace(".", "")
            if len(sub_compact) >= 12 and BASE32_64_CHARS.match(sub_compact):
                self.total_sub_entropy += shannon_entropy(sub_compact)
                self.sub_entropy_samples += 1

        # TXT (qtype 16)
        if qtype == 16:
            self.txt_queries += 1

    def add_response(self, rcode: int):
        # NXDOMAIN rcode=3
        if rcode == 3:
            self.nxdomain += 1


def score(stats: Stats) -> Tuple[float, Dict[str, float]]:
    """
    Produce a 0..100-ish risk score and component metrics.
    """
    if stats.queries == 0:
        return 0.0, {}

    avg_qname_len = stats.total_qname_len / stats.queries
    avg_max_label_len = stats.total_max_label_len / stats.queries
    uniq_ratio = len(stats.unique_qnames) / stats.queries

    sub_uniq_ratio = 0.0
    if stats.queries:
        # unique subdomains per query approximates "many one-offs"
        sub_uniq_ratio = min(1.0, len(stats.unique_subdomains) / stats.queries)

    avg_entropy = (stats.total_sub_entropy / stats.sub_entropy_samples) if stats.sub_entropy_samples else 0.0
    nxd_rate = stats.nxdomain / stats.queries
    txt_rate = stats.txt_queries / stats.queries

    # Heuristic scoring
    s = 0.0

    # Long query names
    if avg_qname_len > 80:
        s += min(20.0, (avg_qname_len - 80) * 0.4)  # ramps up
    if stats.max_qname_len > 150:
        s += min(10.0, (stats.max_qname_len - 150) * 0.2)

    # Long labels
    if avg_max_label_len > 40:
        s += min(15.0, (avg_max_label_len - 40) * 0.6)
    if stats.max_label_len >= 55:
        s += 10.0

    # High entropy subdomains (base32/base64-like)
    # Entropy max for base32-ish is around 5; for base64-ish ~6.
    if avg_entropy > 4.2:
        s += min(25.0, (avg_entropy - 4.2) * 10.0)

    # High uniqueness (many one-off names)
    if uniq_ratio > 0.7:
        s += min(15.0, (uniq_ratio - 0.7) * 50.0)
    if sub_uniq_ratio > 0.5:
        s += min(10.0, (sub_uniq_ratio - 0.5) * 30.0)

    # NXDOMAIN-heavy patterns
    if nxd_rate > 0.3:
        s += min(15.0, (nxd_rate - 0.3) * 40.0)

    # TXT-heavy
    if txt_rate > 0.2:
        s += min(10.0, (txt_rate - 0.2) * 30.0)

    metrics = {
        "avg_qname_len": avg_qname_len,
        "max_qname_len": float(stats.max_qname_len),
        "avg_max_label_len": avg_max_label_len,
        "max_label_len": float(stats.max_label_len),
        "avg_sub_entropy": avg_entropy,
        "uniq_qname_ratio": uniq_ratio,
        "uniq_subdomain_ratio": sub_uniq_ratio,
        "nxdomain_rate": nxd_rate,
        "txt_query_rate": txt_rate,
        "queries": float(stats.queries),
    }
    return min(100.0, s), metrics


def parse_pcap(pcap_path: str) -> Dict[Tuple[str, str], Stats]:
    """
    Aggregates stats keyed by (src_ip, root_domain_guess).
    Counts queries from src->resolver and matches responses by transaction id when possible.
    """
    agg: Dict[Tuple[str, str], Stats] = defaultdict(Stats)

    # Map DNS transaction IDs to (src_ip, root_domain) for response attribution
    tx_map: Dict[Tuple[str, int], Tuple[str, str]] = {}

    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]

            # Query
            if dns.qr == 0 and dns.qdcount >= 1 and dns.qd is not None and isinstance(dns.qd, DNSQR):
                qname = dns.qd.qname.decode(errors="ignore") if isinstance(dns.qd.qname, (bytes, bytearray)) else str(dns.qd.qname)
                qname = qname.strip(".").lower()
                qtype = int(dns.qd.qtype)

                # best-effort src ip extraction
                src_ip = pkt.payload.src if hasattr(pkt.payload, "src") else "unknown"
                root = guess_root_domain(qname)

                agg[(src_ip, root)].add_query(qname, qtype)
                tx_map[(src_ip, int(dns.id))] = (src_ip, root)

            # Response
            elif dns.qr == 1:
                # best-effort dst ip extraction for response mapping
                dst_ip = pkt.payload.dst if hasattr(pkt.payload, "dst") else None
                if dst_ip is None:
                    continue
                key = (dst_ip, int(dns.id))
                if key in tx_map:
                    src_ip, root = tx_map[key]
                    agg[(src_ip, root)].add_response(int(dns.rcode))

    return agg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Path to PCAP file")
    ap.add_argument("--min-queries", type=int, default=60, help="Minimum queries per (src, domain) to score")
    ap.add_argument("--threshold", type=float, default=35.0, help="Score threshold to print alert")
    ap.add_argument("--top", type=int, default=15, help="Show top N by score")
    args = ap.parse_args()

    agg = parse_pcap(args.pcap)

    rows = []
    for (src, root), st in agg.items():
        if st.queries < args.min_queries:
            continue
        sc, m = score(st)
        rows.append((sc, src, root, m))

    rows.sort(reverse=True, key=lambda x: x[0])

    print(f"Analyzed groups (min_queries={args.min_queries}). Showing top {min(args.top, len(rows))}.\n")
    shown = 0
    for sc, src, root, m in rows[: args.top]:
        if sc < args.threshold:
            continue
        shown += 1
        print(f"[ALERT] score={sc:5.1f}  src={src:15}  domain={root}  queries={int(m['queries'])}")
        print(f"  avg_qname_len={m['avg_qname_len']:.1f}  max_qname_len={int(m['max_qname_len'])}")
        print(f"  avg_max_label_len={m['avg_max_label_len']:.1f}  max_label_len={int(m['max_label_len'])}")
        print(f"  avg_sub_entropy={m['avg_sub_entropy']:.2f}  uniq_qname_ratio={m['uniq_qname_ratio']:.2f}  uniq_subdomain_ratio={m['uniq_subdomain_ratio']:.2f}")
        print(f"  nxdomain_rate={m['nxdomain_rate']:.2f}  txt_query_rate={m['txt_query_rate']:.2f}")
        print()

    if shown == 0:
        print(f"No groups exceeded threshold={args.threshold}. (That doesn't prove no tunneling—just no strong heuristic signals.)")


if __name__ == "__main__":
    main()