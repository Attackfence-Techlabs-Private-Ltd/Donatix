#!/usr/bin/env python3
"""Generate the AttackFence Donatix DNS Threat Report as a PDF.

Every chart is followed by a plain-language "What it shows" note and a "Takeaway"
tagged with a level of concern. The takeaways, the executive summary and the
recommended actions are all derived from the captured data by simple rules.

Usage: python generateReport.py [-o report.pdf] [--days N]
"""
import os
import sys
import sqlite3
import argparse
import textwrap
from collections import Counter
from datetime import datetime, timedelta

import matplotlib
matplotlib.use("Agg")  # no display needed, works on headless servers
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import Rectangle, FancyBboxPatch

script_path = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(script_path, "networkdata.db")

# Query packets carry no response code; responses do.
IS_QUERY = "coalesce(rcode, '') = ''"
# On a query the client is the source, on a response it is the destination.
CLIENT = "case when {} then src else dst end".format(IS_QUERY)

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "No Error", 1: "Format Error", 2: "Server Failure",
          3: "Non Existent Domain", 5: "Refused"}

PUBLIC_RESOLVERS = {"8.8.8.8": "Google public DNS", "8.8.4.4": "Google public DNS",
                    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS", "9.9.9.9": "Quad9",
                    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS"}
MULTICAST = {"224.0.0.251", "224.0.0.252", "239.255.255.250", "ff02::fb", "ff02::1:3"}
RISKY_TLDS = {"xyz", "ru", "biz", "top", "info", "tk", "cn", "click", "gq", "ml", "cf", "ga",
              "work", "su", "icu", "buzz"}
TEST_TLDS = {"example", "test", "invalid", "localhost"}
# Reputation feeds often flag shared cloud addresses of these, so a flag on them is
# most likely a false positive. Keyed by the label in front of the public suffix.
MAINSTREAM = {"google": "Google", "gstatic": "Google", "googleapis": "Google", "youtube": "Google",
              "github": "GitHub", "githubusercontent": "GitHub", "discord": "Discord",
              "ubuntu": "Ubuntu", "microsoft": "Microsoft", "windows": "Microsoft",
              "windowsupdate": "Microsoft", "live": "Microsoft", "office": "Microsoft",
              "apple": "Apple", "icloud": "Apple", "amazon": "Amazon", "amazonaws": "Amazon",
              "cloudflare": "Cloudflare", "akamaiedge": "Akamai", "facebook": "Meta",
              "whatsapp": "Meta", "spotify": "Spotify", "msn": "Microsoft", "bing": "Microsoft",
              "microsoftonline": "Microsoft", "azure": "Microsoft", "azureedge": "Microsoft",
              "skype": "Microsoft", "office365": "Microsoft", "xboxlive": "Microsoft",
              "snapcraft": "Ubuntu", "snapcraftcontent": "Ubuntu", "canonical": "Ubuntu",
              "mozilla": "Mozilla", "sectigo": "Sectigo", "usertrust": "Sectigo",
              "digicert": "DigiCert", "letsencrypt": "Let's Encrypt"}
BEACON_MIN = 5          # fewer unanswered requests than this is noise, not a heartbeat
SESSION_GAP = timedelta(hours=6)  # a longer silence splits the timeline into sessions

# AttackFence brand, read straight off the live site's CSS custom properties
# (--color-black, --color-primary, --color-hover, --color-white, --color-heading)
# and sampled from the official wordmark. The report is dark by design: the
# brand's own surface is near-black, so a white page would not be AttackFence.
PAGE_BG = "#160001"   # --color-black, the exact backdrop of the AttackFence site
PANEL = "#210a0c"     # one step up, for panels and table bands
BRAND = "#e51f28"     # --color-primary
BRAND_DIM = "#b71920"  # --color-hover
INK, INK2 = "#ffffff", "#c0c0c0"   # --color-white, --color-heading (silver)
MUTED, GRID, RULE = "#8a7f80", "#332021", "#3d2628"  # sampled from the wordmark
AMBER, GREEN = "#f0a020", "#22a34a"

# Categorical slots, in fixed order. Validated on the #160001 surface: both sit
# in the dark lightness band, clear the chroma floor, and separate by dE 15.0
# under deuteranopia (>= 8) and 33.5 unsimulated (>= 15).
SERIES = [BRAND, "#12a09d"]
# Reserved status colours - never reused as a series hue, always paired with the
# verdict's own label so the meaning never rests on colour alone.
VERDICT_COLORS = {"malicious": "#d03b3b", "is_malicious": "#d03b3b",
                  "suspicious": "#ec835a", "is_suspicious": "#ec835a",
                  "benign": GREEN}
# Level of concern tags: label, background, text colour
LEVELS = {"alert": ("ALERT", BRAND, INK), "review": ("REVIEW", AMBER, "#1a0a00"),
          "normal": ("NORMAL", GREEN, INK), "false": ("LIKELY FALSE ALARM", GREEN, INK)}
PAGE = (11.69, 8.27)  # A4 landscape
# Chart cells on a 2 x 2 page, as (x, y, width, height) in figure fractions
QUAD = [(0.045, 0.47, 0.445, 0.385), (0.51, 0.47, 0.445, 0.385),
        (0.045, 0.07, 0.445, 0.385), (0.51, 0.07, 0.445, 0.385)]

BRAND_DIR = os.path.join(script_path, "brand")
WORDMARK = os.path.join(BRAND_DIR, "af_wordmark.png")
GLOSSARY = [
    ("DNS", "The internet's phonebook. It turns names like example.com into addresses computers use."),
    ("Query / response", "A question to the phonebook and its answer."),
    ("Host", "Any device on the network: laptop, phone, TV, server."),
    ("DGA (domain generation algorithm)", "Malware that invents thousands of random domain names so it "
     "can always find its controller, even if some are blocked."),
    ("Beaconing", "Regular, automatic check-ins from an infected device to its controller, like a heartbeat."),
    ("DNS tunneling", "Hiding other data (stolen files, commands) inside DNS requests so it slips past "
     "security tools."),
    ("C2 (command and control)", "The server that gives orders to malware."),
    ("TXT / ANY / PTR / A", "Kinds of DNS question. A: address of a name. PTR: name for an address. "
     "TXT: free text. ANY: everything."),
    ("Multicast (224.0.0.251)", "Devices announcing themselves to neighbours on the local network. "
     "Normal and usually unanswered."),
    ("TTL", "How long (in seconds) an answer may be remembered before asking again."),
    ("False positive", "A harmless item wrongly flagged as a threat."),
]


def use_brand_font():
    """ Inter is the AttackFence web face; bundled so the sensor needs no network.
        A missing font must never stop a report being produced, so this is soft. """
    try:
        import matplotlib.font_manager as fm
        faces = [os.path.join(BRAND_DIR, f)
                 for f in ("Inter-400.ttf", "Inter-600.ttf", "Inter-700.ttf")]
        faces = [f for f in faces if os.path.exists(f)]
        for face in faces:
            fm.fontManager.addfont(face)
        if faces:
            plt.rcParams["font.family"] = "Inter"
    except Exception as exc:
        print("brand font unavailable, falling back to the default face: {}".format(exc))


use_brand_font()
plt.rcParams.update({
    "figure.facecolor": PAGE_BG, "axes.facecolor": PANEL, "savefig.facecolor": PAGE_BG,
    "text.color": INK, "axes.labelcolor": INK2,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.edgecolor": RULE,
})


# ---------------------------------------------------------------- wording helpers

def n(value):
    return "{:,}".format(value)


def pct(part, whole):
    return round(100.0 * part / whole) if whole else 0


def count_word(value):
    words = ["no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"]
    return words[value] if value < len(words) else n(value)


def plural(value, word):
    return "{} {}{}".format(n(value), word, "" if value == 1 else "s")


def join(items):
    items = list(items)
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def host(label):
    """ tshark only records IPv4 addresses, so IPv6 packets have a blank address """
    return label or "(unknown)"


def duration(span):
    days = span.days
    if days >= 365:
        months = (days % 365) // 30
        return "about {}{}".format(plural(days // 365, "year"),
                                   " " + plural(months, "month") if months else "")
    if days >= 30:
        return "about " + plural(days // 30, "month")
    if days >= 1:
        return "about " + plural(days, "day")
    return "about " + plural(max(span.seconds // 3600, 1), "hour")


def mainstream(name):
    labels = name.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return None
    # google.co.in style names put a second-level label in front of the country code
    key = labels[-3] if labels[-2] in ("co", "com") and len(labels) > 2 else labels[-2]
    return MAINSTREAM.get(key)


def to_time(text):
    return datetime.strptime(text[:16], "%Y-%m-%d %H:%M")


# ---------------------------------------------------------------- drawing helpers

def text_lines(text, width, size):
    """ Wrap to the panel width; Inter averages about half an em per character """
    return textwrap.wrap(text, max(12, int(width * PAGE[0] * 72 / (size * 0.5)))) or [""]


def write(fig, x, y, text, width, size=8, color=INK2, weight="normal"):
    """ Draw wrapped text with its top at y and return the y below it """
    for line in text_lines(text, width, size):
        fig.text(x, y, line, fontsize=size, color=color, fontweight=weight, va="top")
        y -= size * 1.4 / (PAGE[1] * 72)
    return y


def tag(fig, x, y, level, size=6.5):
    label, background, ink = LEVELS[level]
    fig.text(x + 0.004, y, label, fontsize=size, fontweight="bold", color=ink, va="top",
             bbox=dict(boxstyle="round,pad=0.35,rounding_size=0.45", fc=background, ec="none"))


def panel(fig, x, y, w, h, title=None, size=10.5):
    fig.add_artist(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.008",
                                  transform=fig.transFigure, facecolor=PANEL,
                                  edgecolor=RULE, linewidth=0.8, zorder=-1))  # behind the charts
    if title:
        fig.text(x + 0.013, y + h - 0.02, title, fontsize=size, fontweight="bold", color=INK, va="top")


def notes(fig, x, y, w, what, level, takeaway):
    """ The two notes under every chart: what it shows, and what it means """
    fig.text(x, y, "WHAT IT SHOWS", fontsize=6.5, fontweight="bold", color=BRAND, va="top")
    y = write(fig, x, y - 0.019, what, w, 8, MUTED) - 0.008
    fig.text(x, y, "TAKEAWAY", fontsize=6.5, fontweight="bold", color=BRAND, va="top")
    tag(fig, x + 0.052, y + 0.001, level)
    return write(fig, x, y - 0.024, takeaway, w, 8, INK)


def bullets(fig, x, y, w, items, size=8, gap=0.012):
    for item in items:
        y = write(fig, x, y, "• " + item, w, size, INK2) - gap
    return y


def new_page(title, subtitle, number):
    fig = plt.figure(figsize=PAGE)
    fig.text(0.045, 0.925, title, fontsize=20, fontweight="bold", color=INK)
    fig.text(0.045, 0.89, subtitle, fontsize=8, color=INK2)
    # The brand rule: a short solid bar in AttackFence red under the page title
    fig.add_artist(Rectangle((0.045, 0.873), 0.065, 0.005, figure=fig,
                             facecolor=BRAND, edgecolor="none"))
    fig.add_artist(Rectangle((0.11, 0.8745), 0.845, 0.0008, figure=fig,
                             facecolor=RULE, edgecolor="none"))
    if os.path.exists(WORDMARK):
        logo = plt.imread(WORDMARK)
        width = 0.15
        height = width * PAGE[0] * logo.shape[0] / (logo.shape[1] * PAGE[1])
        ax = fig.add_axes([0.955 - width, 0.925, width, height])
        ax.imshow(logo, interpolation="antialiased")
        ax.axis("off")
    fig.text(0.045, 0.03, "AttackFence  |  Donatix DNS Detection and Analytics  |  "
             "Annotated report with plain-language context and takeaways", fontsize=7, color=MUTED)
    fig.text(0.955, 0.03, "Page {}".format(number), fontsize=7, color=MUTED, ha="right")
    return fig


def cell(fig, i, title, what, level, takeaway, label_room=0.15):
    """ One of the four chart cells of a page; returns the axes for the chart """
    x, y, w, h = QUAD[i]
    panel(fig, x, y, w, h, title)
    notes(fig, x + 0.013, y + 0.19, w - 0.026, what, level, takeaway)
    return fig.add_axes([x + label_room, y + 0.21, w - label_room - 0.05, h - 0.255])


def empty(ax, message):
    ax.axis("off")
    ax.text(0.5, 0.5, message, ha="center", va="center", fontsize=9, color=MUTED,
            transform=ax.transAxes)


def hbar(ax, data, colors=BRAND):
    """ Horizontal bar chart of (label, value) pairs, largest first """
    if not data:
        return empty(ax, "No data")
    slots = max(len(data), 6)  # a floor on the slots keeps a short chart's bars slim
    positions = [slots - 1 - i for i in range(len(data))]
    bars = ax.barh(positions, [value for _, value in data], height=0.62, color=colors)
    ax.bar_label(bars, labels=[n(value) for _, value in data], padding=4, fontsize=6.5, color=INK2)
    ax.set_ylim(-0.5, slots - 0.5)
    ax.set_yticks(positions)
    ax.set_yticklabels([host(str(label or ""))[:34] for label, _ in data], fontsize=6.5, color=INK2)
    ax.tick_params(length=0)
    ax.xaxis.set_visible(False)
    ax.margins(x=0.12)
    for side in ("top", "right", "bottom", "left"):
        ax.spines[side].set_visible(False)


def table(ax, columns, data, limit=10, highlight=(), size=7):
    if not data:
        return empty(ax, "None detected")
    ax.axis("off")
    cells = [[str(value)[:38] for value in row] for row in data[:limit]]
    # Rows about two font sizes tall, squeezed if that would overflow the axes
    row = size * 2.1 / 72 / (ax.get_position().height * PAGE[1])
    height = min(1.0, row * (len(cells) + 1))
    tbl = ax.table(cellText=cells, colLabels=columns, cellLoc="left", bbox=[0, 1 - height, 1, height])
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(size)
    tbl.auto_set_column_width(range(len(columns)))
    for (row, _), c in tbl.get_celld().items():
        c.set_linewidth(0)
        if row == 0:
            # Header sits on a red-tinted band, the only chrome that carries the brand
            c.set_facecolor("#3a1014")
            c.get_text().set_color(INK)
            c.get_text().set_fontweight("bold")
        else:
            # Alternating bands, so a long table stays readable on a dark page;
            # rows that are findings get the red band
            c.set_facecolor("#3a1014" if row - 1 in highlight else PANEL if row % 2 else "#1a0507")
            c.get_text().set_color(INK2)


def optional(conn, sql):
    """ Rows of a table that only exists once its detection service has run """
    try:
        return conn.execute(sql).fetchall()
    except sqlite3.OperationalError:
        return []


# ---------------------------------------------------------------- the report

def generate_report(output, days=None):
    if not os.path.exists(db_path):
        sys.exit("Database not found: {}".format(db_path))
    conn = sqlite3.connect(db_path)
    since = str(datetime.now() - timedelta(days=days)) if days else ""

    def query(sql, *params):
        return conn.execute(sql.format(Q=IS_QUERY, C=CLIENT), (since,) + params).fetchall()

    total, queries, first, last = query("""
        select count(*), sum({Q}), min(time), max(time) from dns_query_data where time >= ?""")[0]
    if not queries:
        sys.exit("No DNS data captured for the requested period")
    responses = total - queries
    unanswered = max(queries - responses, 0)
    sample = query("select count(*) from dns_query_data where interface = 'synthetic-test' and time >= ?")[0][0]
    subtitle = "{} to {}{}   |   generated {:%Y-%m-%d %H:%M}".format(
        first[:19], last[:19], "   |   includes labelled sample traffic" if sample else "", datetime.now())

    # ---- who asks for what
    host_rows = query("select src, count(*), count(distinct qname) from dns_query_data "
                      "where {Q} and time >= ? group by 1 order by 2 desc")
    host_queries = {src: count for src, count, _ in host_rows}
    clients = sum(1 for src, _, _ in host_rows if src)
    unknown = host_queries.get("", 0) + host_queries.get(None, 0)
    domains = query("select qname, count(*) from dns_query_data where {Q} and qname != '' "
                    "and time >= ? group by 1 order by 2 desc")
    tlds = Counter()
    for qname, count in domains:
        tlds[qname.rstrip(".").rsplit(".", 1)[-1].lower()] += count
    discovery = sum(count for qname, count in domains
                    if qname.startswith("_") or qname.rstrip(".").endswith(".local"))
    qtypes = Counter()
    for qtype, count in query("select qtype, count(*) from dns_query_data where {Q} and time >= ? group by 1"):
        qtypes[QTYPES.get(qtype, "Other")] += count
    rcodes = query("select rcode, count(*) from dns_query_data where not {Q} and time >= ? "
                   "group by 1 order by 2 desc")
    servers = query("select dst, count(*) from dns_query_data where {Q} and time >= ? "
                    "group by 1 order by 2 desc limit 10")
    stats = []
    for name, column in (("Query name length", "qlen"), ("Label count", "labelcount"), ("TTL (seconds)", "ttl")):
        stats.append((name,) + query("select round(avg({0}), 1), max({0}), min({0}) from dns_query_data "
                                     "where typeof({0}) = 'integer' and time >= ?".format(column))[0])

    # ---- detections
    verdicts = query("select coalesce(nullif(tiVerdict, ''), 'not checked'), count(*) "
                     "from dns_query_data where time >= ? group by 1 order by 2 desc")
    # The verdict belongs to the answer's address when there is one, otherwise to the queried name
    flagged = query("""select qname, case when dnsResponse != '' then dnsResponse else qname end, tiVerdict,
                       count(distinct {C}), count(*) from dns_query_data
                       where lower(tiVerdict) in ('malicious', 'suspicious', 'is_malicious', 'is_suspicious')
                       and time >= ? group by 1, 2, 3 order by 5 desc""")
    dga_domains = query("select qname, count(distinct src), count(*) from dns_query_data "
                        "where isDGA = 1 and {Q} and time >= ? group by 1 order by 3 desc")
    dga_hosts = query("select src, count(*) from dns_query_data where isDGA = 1 and {Q} "
                      "and time >= ? group by 1 order by 2 desc")
    dga_queries = sum(count for _, count in dga_hosts)
    dga_names = "select qname from dns_query_data where isDGA = 1"
    dga_failed, dga_resolved = query(
        "select sum(rcode = 3), sum(rcode = 0 and dnsResponse != '') from dns_query_data "
        "where not {Q} and time >= ? and qname in (%s)" % dga_names)[0]
    dga_failed, dga_resolved = dga_failed or 0, dga_resolved or 0

    beacon_rows = optional(conn, "select srcIp, destIp, max(numQueries), max(numResponses), "
                                 "min(responsePercentage) from beaconingHosts group by 1, 2 order by 3 desc")
    beacons, minor_beacons, multicast_beacons = [], [], []
    for row in beacon_rows:
        if row[1] in MULTICAST:
            multicast_beacons.append(row)
        elif row[2] >= BEACON_MIN and (row[4] or 0) < 50:
            # The name the device asked for points at what is behind the address
            linked = query("select qname from dns_query_data where {Q} and time >= ? and src = ? and dst = ? "
                           "group by 1 order by count(*) desc limit 1", row[0], row[1])
            beacons.append(row + (linked[0][0] if linked else "",))
        else:
            minor_beacons.append(row)

    # The tunneling detector counts queries and responses together; count queries
    # here so the figure matches the domain chart.
    tunnels = []
    for (qname,) in optional(conn, "select distinct qname from dnsTunneling"):
        rows = query("select src, count(*) from dns_query_data where {Q} and time >= ? and qname = ? "
                     "group by 1 order by 2 desc", qname)
        if rows:
            tunnels.append((qname, sum(count for _, count in rows), rows[0][0]))
    tunnels.sort(key=lambda row: -row[1])
    tunnel_hosts = list(dict.fromkeys(row[2] for row in tunnels if row[2]))
    dga_srcs = [src for src, _ in dga_hosts if src]
    beacon_srcs = [row[0] for row in beacons]
    suspects = list(dict.fromkeys(tunnel_hosts + dga_srcs + beacon_srcs))
    findings = (["the {} DGA {}".format(len(dga_domains), "domain" if len(dga_domains) == 1 else "domains")]
                if dga_domains else []) + \
               (["the tunneling {}".format("domain" if len(tunnels) == 1 else "domains")] if tunnels else []) + \
               (["the call-home pattern"] if beacons else [])

    checked = sum(count for verdict, count in verdicts if verdict != "not checked")
    unchecked = total - checked
    false_flags = [row for row in flagged if mainstream(row[0])]
    brands = list(dict.fromkeys(mainstream(row[0]) for row in false_flags))
    real_flags = [row for row in flagged if not mainstream(row[0])]
    public = [(ip, count) for ip, count in servers if ip in PUBLIC_RESOLVERS]
    known_hosts = [row for row in host_rows if row[0]]

    def host_color(src):
        return BRAND if src in tunnel_hosts or src in beacon_srcs else AMBER if src in dga_srcs else MUTED

    # ---- timeline, split wherever capture stopped for a long time
    minutes = [to_time(row[0]) for row in query(
        "select distinct substr(time, 1, 16) from dns_query_data where time >= ? order by 1")]
    sessions, start = [], minutes[0]
    for before, after in zip(minutes, minutes[1:]):
        if after - before > SESSION_GAP:
            sessions.append((start, before))
            start = after
    sessions.append((start, minutes[-1]))
    timelines = []
    for begin, end in sessions:
        # Bucket by minute, hour or day depending on the session's length, stepping
        # finer when that leaves too few points to draw a line from
        span = end - begin
        buckets = [16 if span < timedelta(hours=3) else 13 if span < timedelta(days=3) else 10]
        buckets += [size for size in (13, 16) if size > buckets[0]]
        for bucket in buckets:
            rows = query("select substr(time, 1, %d), sum({Q}), count(*) - sum({Q}) from dns_query_data "
                         "where time >= ? and substr(time, 1, 16) between ? and ? group by 1 order by 1" % bucket,
                         "{:%Y-%m-%d %H:%M}".format(begin), "{:%Y-%m-%d %H:%M}".format(end))
            if len(rows) >= 8:
                break
        timelines.append((begin, end, bucket, rows))
    conn.close()

    with PdfPages(output) as pdf:
        def save(fig):
            pdf.savefig(fig, facecolor=PAGE_BG)
            plt.close(fig)

        # ============================================================ page 1
        fig = new_page("AttackFence Donatix DNS Threat Report", subtitle, 1)
        risky_now = len(suspects)
        if risky_now:
            headline = "HIGH RISK: investigate {} {} now".format(
                count_word(risky_now), "device" if risky_now == 1 else "devices")
        elif public or unknown or pct(checked, total) < 50 or real_flags:
            headline = "MEDIUM RISK: no attack patterns, but gaps to close"
        else:
            headline = "LOW RISK: no attack patterns seen"
        patterns = sum(1 for found in (tunnels, dga_domains, beacons) if found)
        summary = "Out of {} DNS lookups, {}. ".format(
            n(queries), "most is harmless background chatter from devices finding each other"
            if pct(discovery, queries) >= 30 else "most is routine browsing and service traffic")
        summary += ("{} {}, however, {} well-known attack behaviours.".format(
            count_word(patterns).capitalize(), "pattern" if patterns == 1 else "patterns",
            "matches" if patterns == 1 else "match") if patterns else
            "None of it matches the attack behaviours Donatix looks for.")
        if sample and patterns:
            summary += " This report includes labelled sample traffic, so these are treated as test " \
                       "detections that show the tool working."
        fig.add_artist(Rectangle((0.045, 0.76), 0.005, 0.095, figure=fig, facecolor=BRAND, edgecolor="none"))
        panel(fig, 0.045, 0.76, 0.91, 0.095)
        fig.text(0.062, 0.843, "OVERALL ASSESSMENT", fontsize=7, fontweight="bold", color=INK2, va="top")
        fig.text(0.062, 0.825, headline, fontsize=15, fontweight="bold", color=INK, va="top")
        write(fig, 0.062, 0.795, summary, 0.88, 7.5, INK2)

        cards = []
        if tunnels:
            qname, count, src = tunnels[0]
            src_row = next((row for row in host_rows if row[0] == src), (src, 0, 0))
            evidence = ["{}, {}, drew {} of {} lookups ({}%).".format(
                "One domain" if len(tunnels) == 1 else "The top tunneling domain", qname,
                n(count), n(queries), pct(count, queries)),
                "Device {} made {} lookups to only {}.".format(host(src), n(src_row[1]), plural(src_row[2], "name"))]
            long_names = "a {}-character name".format(len(qname)) if len(qname) > 50 else ""
            if pct(qtypes["TXT"], queries) >= 10:
                evidence.append("Unusually high TXT lookups ({}){}.".format(
                    n(qtypes["TXT"]), " and " + long_names if long_names else ""))
            elif long_names:
                evidence.append(long_names.capitalize() + ".")
        else:
            evidence = ["No domain carried enough traffic to look like a data channel."]
        cards.append(("Hidden data theft (DNS tunneling)", "alert" if tunnels else "normal",
                      "DNS is the internet's phonebook. Attackers can abuse it as a hidden pipe to smuggle "
                      "data out, because most firewalls let DNS through.", evidence))
        if dga_domains:
            evidence = ["{} asked for {} gibberish {} ({}).".format(
                join(host(src) for src, _ in dga_hosts) if len(dga_hosts) < 4 else plural(len(dga_hosts), "device"),
                n(len(dga_domains)), "domain" if len(dga_domains) == 1 else "domains", plural(dga_queries, "lookup"))]
            if dga_resolved:
                evidence.append("{} returned an address, so a controller may be live.".format(
                    plural(dga_resolved, "answer")))
            else:
                evidence.append("None resolved to an address{}.".format(
                    ", matching {} \"does not exist\" answers".format(n(dga_failed)) if dga_failed else ""))
                evidence.append("No live controller reached yet, but the behaviour is clear.")
        else:
            evidence = ["No device looked up machine-generated names."]
        cards.append(("Malware hunting for its boss (DGA)", "alert" if dga_domains else "normal",
                      "Some malware invents random website names until it finds its controller. Nothing "
                      "legitimate looks like this.", evidence))
        if beacons:
            src, dst, sent, answered, rate, linked = beacons[0]
            evidence = ["Device {} sent {} check-ins to {}.".format(src, n(sent), dst),
                        "None were answered (0% response)." if not answered else
                        "Only {} answered ({}% response).".format(n(answered), rate)]
            if linked:
                evidence.append("Linked to {}.".format(linked))
            if len(beacons) > 1:
                evidence.append("{} more {} the same pattern.".format(
                    plural(len(beacons) - 1, "device"), "shows" if len(beacons) == 2 else "show"))
        else:
            evidence = ["No device checked in with an unanswering server at a steady rate."]
        cards.append(("Malware calling home (beaconing)", "alert" if beacons else "normal",
                      "Infected devices \"check in\" with their controller at regular intervals, "
                      "like a heartbeat.", evidence))
        for i, (title, level, plain, evidence) in enumerate(cards):
            x, w = 0.045 + i * 0.31, 0.29
            panel(fig, x, 0.41, w, 0.335)
            fig.text(x + 0.023, 0.725, str(i + 1), fontsize=9, fontweight="bold", color=INK, va="center",
                     ha="center", bbox=dict(boxstyle="circle,pad=0.3", fc=BRAND, ec="none"))
            fig.text(x + 0.043, 0.725, title, fontsize=10, fontweight="bold", color=INK, va="center")
            tag(fig, x + 0.013, 0.698, level)
            fig.text(x + 0.013, 0.667, "IN PLAIN WORDS", fontsize=6.5, fontweight="bold", color=BRAND, va="top")
            y = write(fig, x + 0.013, 0.65, plain, w - 0.026, 8.5, INK) - 0.008
            fig.text(x + 0.013, y, "EVIDENCE IN THIS REPORT", fontsize=6.5, fontweight="bold",
                     color=BRAND, va="top")
            bullets(fig, x + 0.013, y - 0.018, w - 0.026, evidence, gap=0.002)

        noise = []
        if false_flags:
            share = "All {}".format(n(len(flagged))) if len(false_flags) == len(flagged) else \
                    "{} of {}".format(n(len(false_flags)), n(len(flagged)))
            noise.append("{} \"suspicious\" reputation flags are on mainstream services: {}. Shared "
                         "cloud addresses often trigger these.".format(share, join(brands)))
        if multicast_beacons:
            noise.append("{} of {} \"beaconing\" rows go to {}, local multicast, where no reply is "
                         "normal.".format(n(len(multicast_beacons)), n(len(beacon_rows)),
                                          join(sorted({row[1] for row in multicast_beacons}))))
        if any(qname.startswith("_") for qname, _ in domains):
            noise.append("Names starting with \"_\" (Chromecast, Spotify, AirPlay and similar) are normal "
                         "device discovery.")
        gaps = []
        if pct(checked, total) < 50:
            gaps.append("Reputation checks covered only {} of {} items (about {}%).".format(
                n(checked), n(total), pct(checked, total)))
        if unknown:
            gaps.append("{} queries could not be tied to any device.".format(n(unknown)))
        for ip, count in public[:1]:
            gaps.append("{} ({}) took {} queries. If devices must use the company resolver, that "
                        "bypasses monitoring.".format(ip, PUBLIC_RESOLVERS[ip], n(count)))
        if pct(unanswered, queries) >= 10:
            gaps.append("{} lookups ({}%) never received an answer.".format(n(unanswered), pct(unanswered, queries)))
        for i, (title, items) in enumerate((("Probably false alarms (noise)",
                                             noise or ["Nothing in this period looks like a false alarm."]),
                                            ("Blind spots to fix", gaps or ["No major visibility gaps."]))):
            x = 0.045 + i * 0.31
            panel(fig, x, 0.07, 0.29, 0.32, title)
            bullets(fig, x + 0.013, 0.34, 0.264, items)
        x = 0.665
        panel(fig, x, 0.07, 0.29, 0.32, "How to read this report")
        y = write(fig, x + 0.013, 0.34, "Every chart is followed by two short notes: What it shows explains the "
                  "chart in everyday language, and Takeaway says what it means for the business. A coloured "
                  "tag gives the level of concern:", 0.264, 8, INK2) - 0.015
        for level, meaning in (("alert", "Likely attack behaviour. Act now."),
                               ("review", "Unusual or a gap. Needs an explanation."),
                               ("normal", "Normal for a healthy network."),
                               ("false", "Flagged, but probably harmless.")):
            tag(fig, x + 0.013, y, level)
            fig.text(x + 0.108, y, meaning, fontsize=7, color=INK2, va="top")
            y -= 0.038
        save(fig)

        # ============================================================ page 2
        fig = new_page("Overview", subtitle, 2)
        small = clients <= 100
        if not flagged:
            flag_text, flag_level = "No reputation flags in this period.", "normal"
        elif not real_flags:
            flag_text, flag_level = "Reputation flags, all on well-known sites. Likely false alarms.", "false"
        else:
            flag_text = "{} on lesser-known sites. Check each one.".format(plural(len(real_flags), "flag"))
            flag_level = "alert" if any("malicious" in str(row[2]).lower() for row in real_flags) else "review"
        tiles = [
            (queries, "DNS queries", "Questions devices asked the internet phonebook. " +
             ("A small network overall." if small else "A large network."), "normal"),
            (responses, "DNS responses",
             "Answers received. About {} ({}%) went unanswered, which needs explaining.".format(
                 n(unanswered), pct(unanswered, queries)) if pct(unanswered, queries) >= 10
             else "Nearly every question was answered.",
             "review" if pct(unanswered, queries) >= 10 else "normal"),
            (clients, "Hosts", "Devices seen on the network." +
             (" Few enough to check one by one." if clients <= 50 else ""), "normal"),
            (len(domains), "Domains queried", "Different names looked up." +
             (" {} of them are computer-generated gibberish.".format(n(len(dga_domains))) if dga_domains else ""),
             "review" if dga_domains else "normal"),
            (len(dga_domains), "DGA domains", "Random names made by software, a known malware trick. "
             "Should be zero." if dga_domains else "Random names made by software. None seen, as it should be.",
             "alert" if dga_domains else "normal"),
            (len(flagged), "Malicious / suspicious", flag_text, flag_level),
        ]
        for i, (value, label, text, level) in enumerate(tiles):
            x = 0.045 + i * 0.1535
            panel(fig, x, 0.655, 0.144, 0.2)
            fig.add_artist(Rectangle((x + 0.012, 0.832), 0.02, 0.004, figure=fig,
                                     facecolor=BRAND, edgecolor="none"))
            fig.text(x + 0.012, 0.82, n(value), fontsize=20, fontweight="bold", color=INK, va="top")
            fig.text(x + 0.012, 0.777, label, fontsize=8, color=INK2, va="top")
            write(fig, x + 0.012, 0.755, text, 0.12, 6.8, INK2)
            tag(fig, x + 0.012, 0.68, level)

        x, y, w, h = 0.045, 0.07, 0.6, 0.57
        panel(fig, x, y, w, h, "Queries and responses over time")
        ax = fig.add_axes([x + 0.035, y + 0.25, w - 0.05, h - 0.32])
        offset, ticks, tick_labels, gap_slots = 0, [], [], 2
        for i, (begin, end, bucket, rows) in enumerate(timelines):
            xs = list(range(offset, offset + len(rows)))
            marker = "o" if len(rows) < 30 else None
            ax.plot(xs, [row[1] for row in rows], color=SERIES[0], linewidth=1.8, marker=marker,
                    markersize=3, label="Queries" if i == 0 else None)
            ax.plot(xs, [row[2] for row in rows], color=SERIES[1], linewidth=1.8, linestyle=(0, (4, 2)),
                    marker=marker, markersize=3, label="Responses" if i == 0 else None)
            if len(timelines) > 1:
                # One centred label per session, so short sessions do not collide
                ticks.append((xs[0] + xs[-1]) / 2)
                tick_labels.append("Session {}\n{:%d %b %H:%M}-{:%H:%M}".format(i + 1, begin, end))
            else:
                step = len(rows) // 6 + 1
                ticks = xs[::step]
                tick_labels = [row[0][5:] for row in rows[::step]]
            # A plain break between sessions; the gap lengths are stated in the note below
            offset += len(rows) + (gap_slots if i + 1 < len(timelines) else 0)
        ax.set_ylim(bottom=0)
        ax.set_xticks(ticks)
        ax.set_xticklabels(tick_labels, fontsize=7, color=MUTED)
        ax.tick_params(length=0, labelsize=7)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        legend = ax.legend(frameon=False, fontsize=8, ncol=2, loc="lower right", bbox_to_anchor=(1, 1.02))
        for text in legend.get_texts():
            text.set_color(INK2)
        for side in ("top", "right", "left", "bottom"):
            ax.spines[side].set_visible(False)
        units = {16: "minute", 13: "hour", 10: "day"}
        if len(timelines) > 1:
            takeaway = " ".join("Session {} ({:%b %Y}) peaks at {} lookups per {}.".format(
                i + 1, begin, n(max(row[1] for row in rows)), units[bucket])
                for i, (begin, _, bucket, rows) in enumerate(timelines))
        else:
            _, _, bucket, rows = timelines[0]
            peak_row = max(rows, key=lambda row: row[1])
            takeaway = "Activity peaks at {} lookups per {} around {}.".format(n(peak_row[1]), units[bucket], peak_row[0])
        if pct(unanswered, queries) >= 10:
            takeaway += " Red stays above teal, so many questions go unanswered, which is typical when " \
                        "traffic goes to servers that do not reply."
        else:
            takeaway += " The two lines track closely, so questions are being answered."
        last_rows = timelines[-1][3]
        if len(last_rows) > 4 and last_rows[-1][1] < 0.25 * sorted(row[1] for row in last_rows)[len(last_rows) // 2]:
            takeaway += " The drop on the far right is most likely the capture stopping, not the network " \
                        "going quiet."
        what = "The number of DNS questions (solid red) and answers received (dashed teal) in each time slice."
        if len(timelines) > 1:
            what += " The {} capture sessions are shown side by side; capture was paused for {} between " \
                    "them.".format(count_word(len(timelines)), join(
                        duration(after[0] - before[1]) for before, after in zip(timelines, timelines[1:])))
        notes(fig, x + 0.013, y + 0.2, w - 0.026, what,
              "review" if pct(unanswered, queries) >= 10 else "normal", takeaway)

        panel(fig, 0.66, 0.07, 0.295, 0.57, "What management should take from this page", 9.5)
        points = [("Scale is {}.".format("small" if small else "large"),
                   "{} devices and {} domains{}".format(n(clients), n(len(domains)),
                                                       ": every unusual item can be reviewed by hand."
                                                       if small and len(domains) < 500 else "."))]
        if known_hosts and pct(known_hosts[0][1], queries) >= 25:
            points.append(("Activity is not evenly spread.", "One device ({}) produces about {}% of it "
                           "(page 4).".format(known_hosts[0][0], pct(known_hosts[0][1], queries))))
        else:
            points.append(("Activity is spread out.", "No single device dominates the traffic."))
        if pct(unanswered, queries) >= 10:
            points.append(("The unanswered traffic is the clue.", "{} lookups got no reply. Ordinary websites "
                           "nearly always answer, while attacker infrastructure and test domains often "
                           "do not.".format(n(unanswered))))
        if findings and flagged and not real_flags:
            points.append(("The {} \"suspicious\" flags are not the real problem.".format(n(len(flagged))),
                           "The real findings are {} on pages 5 and 6.".format(join(findings))))
        elif findings:
            points.append(("Real findings.", "{} on pages 5 and 6.".format(join(findings)[0].upper() + join(findings)[1:])))
        else:
            points.append(("No attack pattern found.", "The items to review are the gaps on page 1."))
        y = 0.585
        for lead, body in points:
            y = write(fig, 0.673, y, lead, 0.27, 8.5, INK, "bold")
            y = write(fig, 0.673, y, body, 0.27, 8.5, INK2) - 0.018
        save(fig)

        # ============================================================ page 3
        fig = new_page("Traffic Breakdown", subtitle, 3)
        txt, any_, ptr = qtypes["TXT"], qtypes["ANY"], qtypes["PTR"]
        address = qtypes["A"] + qtypes["AAAA"] + qtypes["HTTPS"]
        high = (["TXT ({})".format(n(txt))] if pct(txt, queries) >= 10 else []) + \
               (["ANY ({})".format(n(any_))] if pct(any_, queries) >= 5 else [])
        if high:
            level = "review"
            takeaway = "On a healthy network A and AAAA dominate. Here {} {} unusually high.".format(
                join(high), "is" if len(high) == 1 else "are")
            if pct(txt, queries) >= 10:
                takeaway += " TXT is a favourite way to smuggle data through DNS."
            if pct(any_, queries) >= 5:
                takeaway += " ANY asks for every record at once, which scanning tools and some device " \
                            "discovery use."
        else:
            level = "normal"
            takeaway = "Address lookups (A, AAAA, HTTPS) make up {}% of questions, as expected on a healthy " \
                       "network.".format(pct(address, queries))
        if pct(ptr, queries) >= 25:
            takeaway += " The high PTR count ({}) is mostly local device discovery.".format(n(ptr))
        ax = cell(fig, 0, "Query types", "The kind of question being asked. A and AAAA mean \"what is this "
                  "website's address?\", PTR means \"who owns this address?\", and TXT means \"give me the "
                  "free-text note attached to this name\".", level, takeaway, 0.08)
        hbar(ax, qtypes.most_common(8))

        ok = sum(count for rcode, count in rcodes if rcode == 0)
        nx = sum(count for rcode, count in rcodes if rcode == 3)
        if not responses:
            level, takeaway = "review", "No answers were captured, so nothing can be said about failures."
        elif dga_failed:
            level = "alert"
            takeaway = "{}% of answers were normal. {} of the {} \"does not exist\" failures were lookups of " \
                       "gibberish DGA names (page 5){}. That is a strong sign of malware searching for its " \
                       "controller.".format(pct(ok, responses), n(dga_failed), n(nx),
                                            ", so every failed lookup was a machine-generated name"
                                            if dga_failed == nx else "")
        elif pct(nx, responses) >= 10:
            level = "review"
            takeaway = "{}% of answers say the name does not exist. Misconfigured software or malware can " \
                       "cause this; check which devices are behind it.".format(pct(nx, responses))
        else:
            level = "normal"
            takeaway = "{}% of answers were normal; failures are at an everyday level.".format(pct(ok, responses))
        ax = cell(fig, 1, "Response codes", "Whether each answer was successful. \"No Error\" is a good answer. "
                  "\"Non Existent Domain\" means the name asked for does not exist.", level, takeaway)
        hbar(ax, [(RCODES.get(rcode, "Code {}".format(rcode)), count) for rcode, count in rcodes[:8]],
             colors=[GREEN if rcode == 0 else BRAND if rcode == 3 else AMBER for rcode, _ in rcodes[:8]])

        top_tlds = tlds.most_common(10)
        parts, level = [], "normal"
        if tlds["local"]:
            parts.append("\".local\" ({}) is internal device discovery and is normal.".format(n(tlds["local"])))
        for tld in sorted(TEST_TLDS & set(tlds)):
            level = "review"
            parts.append("\".{}\" ({}) is a reserved test ending that never exists on the real internet{}".format(
                tld, n(tlds[tld]), ", confirming the sample traffic." if sample else
                ". Something is querying made-up names."))
        risky = [tld for tld, _ in top_tlds if tld in RISKY_TLDS]
        if risky:
            level = "review"
            dga_tlds = {qname.rstrip(".").rsplit(".", 1)[-1].lower() for qname, _, _ in dga_domains}
            parts.append("The counts for {} are endings attackers favour for cheap throwaway domains{}".format(
                join("." + tld for tld in risky), ", and they match the DGA list." if dga_tlds & set(risky) else "."))
        if level == "normal":
            parts.append("The usual endings dominate; nothing unusual.")
        ax = cell(fig, 2, "Top level domains (the ending of a web address)",
                  "Which address endings were queried most, such as .com or .local.", level, " ".join(parts), 0.08)
        hbar(ax, top_tlds)

        parts, level = [], "normal"
        for ip, count in public[:1]:
            level = "review"
            parts.append("{} ({}) took {} queries. If policy says devices must use the company resolver, this "
                         "bypasses your monitoring and filtering.".format(ip, PUBLIC_RESOLVERS[ip], n(count)))
        for ip, _ in servers:
            if ip in MULTICAST:
                parts.append("{} is local multicast and normal.".format(ip))
        for ip, count in servers:
            if ip in {row[1] for row in beacons}:
                level = "alert"
                parts.append("{} ({} queries) matches the call-home pattern on page 6.".format(ip, n(count)))
        unknown_servers = sum(count for ip, count in servers if not ip)
        if unknown_servers:
            level = "alert" if level == "alert" else "review"
            parts.append("The {} \"unknown\" entries are a visibility gap.".format(n(unknown_servers)))
        ax = cell(fig, 3, "DNS servers by queries", "Which DNS servers (the \"phonebook operators\") devices "
                  "sent their questions to.", level, " ".join(parts) or "Lookups go to the expected resolvers.", 0.1)
        hbar(ax, servers)
        save(fig)

        # ============================================================ page 4
        fig = new_page("Hosts and Domains", subtitle, 4)
        parts, level = [], "normal"
        top10 = domains[:10]
        tunnel_names = {row[0] for row in tunnels}
        beacon_names = {row[5] for row in beacons if row[5]}
        for qname, count in top10:
            if qname in tunnel_names:
                level = "alert"
                parts.append("{} has {} lookups, {} of all traffic, and the tunneling detector flagged it "
                             "(page 6).".format(
                                 qname, n(count), "over a third" if pct(count, queries) > 33
                                 else "about {}%".format(pct(count, queries))))
        if top10 and not parts:
            qname, count = top10[0]
            if pct(count, queries) >= 25 and not qname.startswith("_"):
                level = "review"
                parts.append("{} draws {}% of all lookups; confirm it is expected.".format(qname, pct(count, queries)))
        for qname in [qname for qname, _ in top10 if qname in beacon_names]:
            level = "alert"
            parts.append("{} looks like a routine service name but behaves like a malware check-in.".format(qname))
        if any(qname.startswith("_") or qname.rstrip(".").endswith(".local") for qname, _ in top10):
            parts.append("Names starting with \"_\" or ending in .local are devices announcing themselves.")
        if any("'s " in qname for qname, _ in top10):
            parts.append("One entry also exposes a person's device name, a minor privacy leak.")
        ax = cell(fig, 0, "Top domains by queries", "The most-requested names. Names starting with \"_\" are "
                  "devices announcing themselves on the local network (Chromecast, Spotify, Apple AirPlay, "
                  "Microsoft).", level, " ".join(parts) or "Top names are ordinary services; nothing stands out.", 0.17)
        hbar(ax, top10, colors=[BRAND if qname in tunnel_names | beacon_names else MUTED for qname, _ in top10])

        top_hosts = host_rows[:10]
        parts, level = [], "normal"
        if known_hosts:
            src, count, _ = known_hosts[0]
            if src in suspects:
                level = "alert"
                parts.append("Device {} made {} lookups, about {}% of everything, and is linked to the findings, "
                             "so it is the first device to investigate.".format(src, n(count), pct(count, queries)))
            elif pct(count, queries) >= 40:
                level = "review"
                parts.append("Device {} made {} lookups, about {}% of everything. Confirm what it is.".format(
                    src, n(count), pct(count, queries)))
            else:
                parts.append("Lookups are spread across devices; the busiest, {}, made {}%.".format(
                    src, pct(count, queries)))
            for other, count, _ in top_hosts:
                if other and other != src and other in suspects:
                    level = "alert"
                    parts.append("Device {} ({} lookups) is linked to the findings and should be investigated "
                                 "first.".format(other, n(count)))
        if unknown:
            level = "alert" if level == "alert" else "review"
            parts.append("The {} unknown-source lookups are a visibility gap that should be closed.".format(n(unknown)))
        ax = cell(fig, 1, "Queries by host", "How many lookups each device (host) made. \"(unknown)\" means the "
                  "tool could not tell which device sent them.", level, " ".join(parts))
        hbar(ax, [(src, count) for src, count, _ in top_hosts], colors=[host_color(src) for src, _, _ in top_hosts])

        by_names = sorted(top_hosts, key=lambda row: -row[2])
        parts, level = [], "normal"
        if known_hosts:
            user = max(known_hosts, key=lambda row: row[2])
            parts.append("{} looks like a normal user ({} lookups across {} sites).".format(user[0], n(user[1]), n(user[2])))
        for src, count, names in known_hosts:
            if src in tunnel_hosts:
                level = "alert"
                parts.append("Device {} is the opposite: {} lookups to only {}, the signature of data leaving "
                             "through DNS.".format(src, n(count), plural(names, "name")))
        # Smart TVs, speakers and printers also repeat a few names, so the rest get one capped line
        automated = [src for src, count, names in known_hosts
                     if src not in tunnel_hosts and src not in dga_srcs and count >= 100 and names <= 5]
        if automated:
            level = "review" if level == "normal" else level
            parts.append("{} also {} 100+ lookups to 5 names or fewer ({}{}). Usually smart devices, but "
                         "worth confirming.".format(plural(len(automated), "other device"),
                                                    "makes" if len(automated) == 1 else "make",
                                                    ", ".join(automated[:3]), ", ..." if len(automated) > 3 else ""))
        for src, count, names in by_names:
            if src in dga_srcs:
                level = "alert"
                parts.append("Device {} ({}) is also notable because it is a DGA host.".format(src, plural(names, "name")))
        ax = cell(fig, 2, "Distinct domains visited by host", "How many different sites each device contacted. "
                  "Normal users browse many sites. Compromised or automated devices often talk to very few.",
                  level, " ".join(parts))
        hbar(ax, [(src, names) for src, _, names in by_names], colors=[host_color(src) for src, _, _ in by_names])

        name_len, labels, ttl = stats
        parts, level = [], "normal"
        if (name_len[2] or 0) > 50 or (labels[2] or 0) > 5:
            level = "review"
            parts.append("Averages look normal, but names up to {} characters and up to {} parts suggest some "
                         "carry hidden data.".format(name_len[2], labels[2]))
        else:
            parts.append("Name lengths and label counts are in the normal range.")
        if ttl[3] == 0:
            level = "review"
            parts.append("A TTL of 0 means answers are not cached, which attackers use to switch destinations "
                         "quickly.")
        ax = cell(fig, 3, "Query name length, label count and TTL", "Technical fingerprints. Length is the number "
                  "of characters in the name, labels are its dot-separated parts, and TTL is how many seconds an "
                  "answer may be remembered.", level, " ".join(parts), 0.03)
        table(ax, ["Metric", "Average", "Maximum", "Minimum"],
              [tuple("-" if value is None else value for value in row) for row in stats], size=8)
        save(fig)

        # ============================================================ page 5
        fig = new_page("Threat Intelligence and DGA Detection", subtitle, 5)
        coverage = pct(checked, total)
        if not checked:
            level, takeaway = "review", "No item has been checked against threat intel yet. Check the threat " \
                                        "intel licence and that the checking service is running."
        elif coverage < 50:
            level = "review"
            takeaway = "Only {} items were checked and {} were not, so reputation coverage is about {}%. Do not " \
                       "read this chart as a clean bill of health. Widening coverage is the quickest way to " \
                       "improve confidence.".format(n(checked), n(unchecked), coverage)
        else:
            level, takeaway = "normal", "{}% of items were checked against threat intel.".format(coverage)
        checked_rows = [row for row in verdicts if row[0] != "not checked"]
        ax = cell(fig, 0, "Threat intel verdicts  |  {} not checked".format(n(unchecked)),
                  "How outside reputation databases rated the addresses that were checked: benign (safe), "
                  "suspicious, or unknown.", level, takeaway, 0.08)
        hbar(ax, checked_rows, colors=[VERDICT_COLORS.get(str(v).lower(), MUTED) for v, _ in checked_rows])

        if not flagged:
            level, takeaway = "normal", "No address or domain was flagged by reputation sources."
        elif real_flags:
            level = flag_level
            takeaway = "{} {} not well-known services: {}. Investigate these first.".format(
                plural(len(real_flags), "flagged item"), "is" if len(real_flags) == 1 else "are",
                join(sorted({row[0] for row in real_flags})[:4]))
            if false_flags:
                takeaway += " The rest are on mainstream services ({}) and are most likely false " \
                            "positives.".format(join(brands))
        else:
            level = "false"
            takeaway = "Every flagged domain is a mainstream service ({}). These are most likely false positives " \
                       "caused by shared cloud addresses. Review them but do not escalate on their own. The " \
                       "tool needs allow-list tuning to cut this noise.".format(join(brands))
        x, y, w, h = QUAD[1]
        panel(fig, x, y, w, h, "Flagged indicators" + (" (top 10 of {})".format(len(flagged)) if len(flagged) > 10 else ""))
        notes(fig, x + 0.013, y + 0.19, w - 0.026, "Addresses that reputation sources marked suspicious, and "
              "which domain they belong to.", level, takeaway)
        table(fig.add_axes([x + 0.013, y + 0.21, w - 0.026, h - 0.255]),
              ["Domain", "Indicator", "Verdict", "Hosts", "Pkts"], flagged,
              highlight={i for i, row in enumerate(flagged[:10]) if not mainstream(row[0])}, size=6.5)

        if dga_hosts:
            src, count = dga_hosts[0]
            takeaway = "{} {} involved: {}. Malware uses this trick to find its controller when a fixed address " \
                       "gets blocked. These are the strongest suspected infections.".format(
                           count_word(len(dga_hosts)).capitalize(), "device is" if len(dga_hosts) == 1 else "devices are",
                           join("{} ({} lookups)".format(host(s), n(c)) for s, c in dga_hosts[:4]))
            if host_queries.get(src):
                takeaway += " For {}, {} of its {} lookups (about {}%) were DGA.".format(
                    host(src), n(count), n(host_queries[src]), pct(count, host_queries[src]))
            level = "alert"
        else:
            level, takeaway = "normal", "No device looked up machine-generated names."
        ax = cell(fig, 2, "DGA queries by host", "Which devices looked up \"algorithm-generated\" names: "
                  "random-looking domains made by software instead of chosen by people.", level, takeaway, 0.1)
        hbar(ax, dga_hosts[:10])

        if dga_domains:
            tries = [row[2] for row in dga_domains]
            takeaway = "The names are gibberish, tried {} each".format(
                "{} to {} times".format(min(tries), max(tries)) if min(tries) != max(tries) else plural(tries[0], "time"))
            takeaway += (", and none resolved. No live controller was reached yet, but the behaviour is "
                         "unmistakable." if not dga_resolved else
                         ". {} returned an address, so a controller may be live.".format(plural(dga_resolved, "lookup")))
            takeaway += " Block these domains and add them to watch-lists."
            level = "alert"
        else:
            level, takeaway = "normal", "No machine-generated names were seen."
        x, y, w, h = QUAD[3]
        panel(fig, x, y, w, h, "DGA domains" + (" (top 10 of {})".format(len(dga_domains)) if len(dga_domains) > 10 else ""))
        hosts_note = " Each was queried by one device." if dga_domains and all(row[1] == 1 for row in dga_domains) else ""
        notes(fig, x + 0.013, y + 0.19, w - 0.026, "The random-looking names that were tried." + hosts_note,
              level, takeaway)
        table(fig.add_axes([x + 0.013, y + 0.21, w - 0.026, h - 0.255]), ["Domain", "Hosts", "Queries"],
              dga_domains, size=6.5)
        save(fig)

        # ============================================================ page 6
        fig = new_page("Beaconing and DNS Tunneling Detection", subtitle, 6)
        x, y, w, h = 0.045, 0.43, 0.52, 0.425
        panel(fig, x, y, w, h, "Beaconing hosts")
        if beacons:
            src, dst, sent, answered, _, linked = beacons[0]
            takeaway = "The row that matters is {} to {}: {} requests and {} replies{}. That is classic call-home " \
                       "behaviour.".format(src, dst, n(sent), n(answered),
                                           ", matching the \"{}\" domain on page 4".format(linked) if linked else "")
            if len(beacons) > 1:
                takeaway += " {} more {} the same pattern.".format(plural(len(beacons) - 1, "row"),
                                                                   "shows" if len(beacons) == 2 else "show")
            level = "alert"
        else:
            level, takeaway = "normal", "No device keeps contacting a destination that never answers."
        if multicast_beacons:
            takeaway += " The {} to local multicast are noise, since no reply is normal there.".format(
                plural(len(multicast_beacons), "row"))
        if minor_beacons:
            recheck = sorted({row[0] for row in minor_beacons if row[0] in dga_srcs})
            takeaway += " {} under {} requests {} minor{}.".format(
                plural(len(minor_beacons), "row"), BEACON_MIN, "is" if len(minor_beacons) == 1 else "are",
                ", but worth a recheck because {} {} also a DGA host".format(
                    join(recheck), "is" if len(recheck) == 1 else "are") if recheck else "")
        notes(fig, x + 0.013, y + 0.185, w - 0.026, "Devices that repeatedly contact one destination and get no "
              "reply, like a regular \"I am alive\" ping.", level, takeaway)
        table(fig.add_axes([x + 0.013, y + 0.2, w - 0.026, h - 0.245]),
              ["Source", "Destination", "Requests", "Responses", "Response %"],
              [row[:5] for row in beacons + minor_beacons + multicast_beacons], limit=8,
              highlight=set(range(len(beacons))))

        x, w = 0.58, 0.375
        panel(fig, x, y, w, h, "DNS tunneling domains")
        if tunnels:
            qname, count, src = tunnels[0]
            evidence = []
            if pct(txt, queries) >= 10:
                evidence.append("the heavy TXT use")
            if len(qname) > 50:
                evidence.append("a long name that can carry encoded data")
            src_row = next((row for row in host_rows if row[0] == src), None)
            if src_row and src_row[2] <= 5:
                evidence.append("one device talking to only {}".format(plural(src_row[2], "name")))
            takeaway = "{} is the most serious finding: a channel that can move data out of the network while " \
                       "looking like ordinary DNS.".format(qname)
            if evidence:
                takeaway += " Together with {}, it is consistent with data theft.".format(join(evidence))
            level = "alert"
        else:
            level, takeaway = "normal", "No domain shows the volume and payload pattern of data hidden in DNS."
        notes(fig, x + 0.013, y + 0.185, w - 0.026, "Domains where DNS appears to be carrying data, instead of "
              "just looking up addresses. Queries only, so the counts match page 4.", level, takeaway)
        table(fig.add_axes([x + 0.013, y + 0.2, w - 0.026, h - 0.245]), ["Domain", "Queries", "Top device"],
              [(qname, n(count), host(src)) for qname, count, src in tunnels], limit=8)

        panel(fig, 0.045, 0.07, 0.91, 0.34, "Data quality notes for the tool owners")
        dq = []
        if len(timelines) > 1:
            gaps_between = [duration(after[0] - before[1]) for before, after in zip(timelines, timelines[1:])]
            dq.append(("Separate capture sessions.", "The data holds {} capture sessions with {} {} between "
                       "them. Page 2 shows them side by side.".format(
                           count_word(len(timelines)), "a gap of" if len(gaps_between) == 1 else "gaps of",
                           join(gaps_between))))
        if sample:
            dq.append(("Test and live traffic mixed.", "{} rows are labelled sample traffic (interface "
                       "'synthetic-test'). Remove them before sharing this report with management.".format(n(sample))))
        if multicast_beacons:
            dq.append(("Multicast noise in beaconing.", "The beaconing detector reports local multicast ({}). "
                       "This report lists those rows but does not count them as findings.".format(
                           join(sorted({row[1] for row in multicast_beacons})))))
        if tunnels:
            dq.append(("Tunneling counts are queries only.", "The tunneling detector counts queries and "
                       "responses together. This report counts queries only, so the figures agree with page 4."))
        if unknown:
            dq.append(("Unattributed queries.", "{} queries have no recorded source address, typically IPv6 "
                       "traffic the sensor does not yet attribute to a device.".format(n(unknown))))
        if not checked:
            dq.append(("No threat intel results.", "No row carries a reputation verdict. Check the threat intel "
                       "licence and service."))
        if not dq:
            dq.append(("No data quality issues.", "Nothing in this period needs the tool owners' attention."))
        for i, (lead, body) in enumerate(dq[:6]):
            col_x = 0.058 + (i % 2) * 0.45
            row_y = write(fig, col_x, 0.355 - (i // 2) * 0.09, lead, 0.42, 8, INK, "bold")
            write(fig, col_x, row_y, body, 0.42, 8, INK2)
        save(fig)

        # ============================================================ page 7
        fig = new_page("Recommended Next Steps and Glossary", subtitle, 7)
        actions = []
        if suspects:
            behaviours = (["data-theft"] if tunnel_hosts else []) + (["DGA"] if dga_srcs else []) + \
                         (["call-home"] if beacon_srcs else [])
            actions.append(("alert", "Isolate and investigate {} {}.".format(
                "device" if len(suspects) == 1 else "devices", join(suspects)),
                "They show {} behaviour. Contain first, then check for malware.".format(join(behaviours))))
        blocks = [row[0] for row in tunnels] + \
                 (["the {} DGA {}".format(len(dga_domains), "domain" if len(dga_domains) == 1 else "domains")]
                  if dga_domains else []) + \
                 list(dict.fromkeys(row[5] for row in beacons if row[5])) + \
                 list(dict.fromkeys(row[1] for row in beacons))
        if blocks:
            actions.append(("alert", "Block {}.".format(join(blocks)), "Cuts off the suspected {} at the DNS and "
                            "firewall level.".format(join((["data channel"] if tunnels else []) +
                                                          (["command servers"] if dga_domains or beacons else [])))))
        if real_flags:
            actions.append((flag_level, "Investigate the {} on lesser-known sites.".format(
                plural(len(real_flags), "reputation hit")),
                "Unlike the mainstream-service flags, these are not explained by shared cloud addresses."))
        for ip, _ in public[:1]:
            actions.append(("review", "Confirm whether devices may use {} directly.".format(ip),
                            "If not, force all lookups through the company resolver so nothing bypasses monitoring."))
        if unknown:
            actions.append(("review", "Close the visibility gaps: {} unknown-source queries.".format(n(unknown)),
                            "Unattributed traffic cannot be investigated. Fix sensor placement or logging."))
        if coverage < 50:
            actions.append(("review", "Expand threat-intel coverage beyond about {}% of items.".format(coverage)
                            if checked else "Restore threat-intel checks; no item has a verdict.",
                            "Low coverage gives false comfort. Check all domains and addresses."))
        if false_flags or multicast_beacons:
            actions.append(("normal", "Tune the tool: {}.".format(join(
                (["allow-list mainstream services"] if false_flags else []) +
                (["exclude multicast from beaconing"] if multicast_beacons else []))),
                "Fewer false alarms means analysts focus on real threats."))
        if not actions:
            actions.append(("normal", "No action needed. Keep monitoring and rerun this report weekly.",
                            "Nothing in this period points to an attack or a visibility gap."))
        panel(fig, 0.045, 0.07, 0.505, 0.785, "Recommended actions, in priority order")
        y = 0.8
        for i, (level, action, why) in enumerate(actions[:8]):
            fig.text(0.058, y, str(i + 1), fontsize=14, fontweight="bold", color=BRAND, va="top")
            tag(fig, 0.078, y - 0.002, level)
            y = write(fig, 0.08, y - 0.027, action, 0.45, 8.5, INK, "bold")
            y = write(fig, 0.08, y - 0.002, "Why: " + why, 0.45, 7.5, MUTED) - 0.018
        panel(fig, 0.565, 0.07, 0.39, 0.785, "Plain-language glossary")
        y = 0.8
        for term, meaning in GLOSSARY:
            fig.text(0.578, y, term, fontsize=8, fontweight="bold", color=BRAND, va="top")
            y = write(fig, 0.578, y - 0.018, meaning, 0.36, 7.5, INK2) - 0.016
        save(fig)
    print("Report written to {}".format(os.path.abspath(output)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the DNS threat report as a PDF")
    parser.add_argument("-o", "--output", default="Donatix_Report_{:%Y-%m-%d}.pdf".format(datetime.now()))
    parser.add_argument("--days", type=int, help="only report on the last N days (default: all data)")
    args = parser.parse_args()
    generate_report(args.output, args.days)
