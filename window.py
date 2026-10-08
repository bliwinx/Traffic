import queue
import time
import tkinter as tk
from tkinter import ttk

import PP26


MAX_LINES = 500
MAX_PER_TICK = 50
BLOCKED_SHOWN = 5   


REASON_FIELDS = ("reason", "rule", "block_reason")
SIZE_FIELDS = ("size", "length", "len", "bytes")

PORT_NAMES = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    123: "NTP",
}

theme = [
    "#f5f1eb",  
    "#fffdf9", 
    "#ece5db",  
    "#302d2a",  
    "#766e65",  
    "#56806a",  
    "#c6534b",  
    "#ddd3c7", 
    "#e8ded1",  
    "#e0d6ca",  
]

records = []


def get_reason(rec):
    for field in REASON_FIELDS:
        value = getattr(rec, field, None)
        if value:
            return str(value)
    return "Not specified"


def get_size(rec):
    for field in SIZE_FIELDS:
        value = getattr(rec, field, None)
        if isinstance(value, (int, float)):
            return int(value)
    return None


def format_size(size):
    if size is None:
        return "-"
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 ** 2:.1f} MB"


def make_record(rec):
    sport = getattr(rec, "sport", None)
    dport = getattr(rec, "dport", None)

    source = str(rec.src)
    destination = str(rec.dst)

    if sport:
        source += f":{sport}"
    if dport:
        destination += f":{dport}"

    service = (
        PORT_NAMES.get(dport)
        or PORT_NAMES.get(sport)
        or "Unknown"
    )

    raw_status = str(getattr(rec, "status", "")).lower()
    status = "Allowed" if raw_status == "allowed" else "Blocked"

    return {
        "time": time.strftime("%H:%M:%S", time.localtime(rec.time)),
        "proto": str(rec.proto).upper(),
        "src": source,
        "dst": destination,
        "service": service,
        "domain": getattr(rec, "dns_name", "") or "",
        "size": get_size(rec),
        "status": status,
        "reason": get_reason(rec) if status == "Blocked" else "",
    }


def show_records():
    tree.delete(*tree.get_children())

    protocol_filter = protocol_var.get()
    status_filter = status_var.get()
    service_filter = service_var.get()
    search_text = search_var.get().strip().lower()

    for record in reversed(records):
        if protocol_filter != "All" and record["proto"] != protocol_filter:
            continue

        if status_filter != "All" and record["status"] != status_filter:
            continue

        if service_filter != "All" and record["service"] != service_filter:
            continue

        searchable = " ".join((
            record["src"],
            record["dst"],
            record["domain"],
            record["proto"],
            record["service"],
        )).lower()

        if search_text and search_text not in searchable:
            continue

        tag = "blocked" if record["status"] == "Blocked" else "allowed"

        tree.insert(
            "",
            "end",
            values=(
                record["time"],
                record["proto"],
                record["src"],
                record["dst"],
                record["service"],
                record["domain"],
                format_size(record["size"]),
                record["status"],
            ),
            tags=(tag,),
        )


def show_blocked():
    blocked_tree.delete(*blocked_tree.get_children())

    shown = 0
    for record in reversed(records):
        if record["status"] != "Blocked":
            continue

        blocked_tree.insert(
            "",
            "end",
            values=(
                record["time"],
                record["proto"],
                record["src"],
                record["dst"],
                record["service"],
                format_size(record["size"]),
                record["reason"],
            ),
            tags=("blocked",),
        )

        shown += 1
        if shown >= BLOCKED_SHOWN:
            break


def poll_queue():
    new_records = []

    for _ in range(MAX_PER_TICK):
        try:
            rec = PP26.traffic_queue.get_nowait()
        except queue.Empty:
            break

        try:
            new_records.append(make_record(rec))
        except Exception as error:
            print("Bad record skipped:", error)

    if new_records:
        records.extend(new_records)

        if len(records) > MAX_LINES:
            del records[:-MAX_LINES]

        show_blocked()
        show_records()

    window_r.after(100, poll_queue)


def clear_search():
    search_var.set("")
    search_entry.focus_set()


#------------------------------------------------------------

window_r = tk.Tk()
window_r.title("Traffic Monitor")
window_r.configure(bg=theme[0])
window_r.minsize(950, 600)
try:
    window_r.state("zoomed")
except tk.TclError:
    pass


#------------------------------------------------------------


top = tk.Frame(window_r, bg=theme[0])
top.pack(fill="x", padx=22, pady=(18, 14))

tk.Label(
    top,
    text="Network traffic",
    bg=theme[0],
    fg=theme[3],
    font=("Segoe UI", 23, "bold"),
).pack(anchor="w")

tk.Label(
    top,
    text="Allowed and blocked connections",
    bg=theme[0],
    fg=theme[4],
    font=("Segoe UI", 11),
).pack(anchor="w", pady=(3, 0))

#------------------------------------------------------------

blocked_card = tk.Frame(
    window_r,
    bg=theme[1],
    highlightbackground=theme[7],
    highlightthickness=1,
)
blocked_card.pack(fill="x", padx=22, pady=(0, 14))

tk.Label(
    blocked_card,
    text=f"LAST {BLOCKED_SHOWN} BLOCKED CONNECTIONS",
    bg=theme[1],
    fg=theme[6],
    font=("Segoe UI", 10, "bold"),
).pack(anchor="w", padx=14, pady=(10, 6))

blocked_columns = ("time", "proto", "src", "dst", "service", "size", "reason")

blocked_tree = ttk.Treeview(
    blocked_card,
    columns=blocked_columns,
    show="headings",
    height=BLOCKED_SHOWN,
    selectmode="none",
)

blocked_info = {
    "time": ("Time", 85),
    "proto": ("Protocol", 85),
    "src": ("Source", 180),
    "dst": ("Destination", 180),
    "service": ("Service", 100),
    "size": ("Size", 80),
    "reason": ("Reason", 300),
}

for key, (heading, width) in blocked_info.items():
    blocked_tree.heading(key, text=heading)
    blocked_tree.column(
        key,
        width=width,
        minwidth=65,
        anchor="w"
        
    )

blocked_tree.column("size", anchor="center")
blocked_tree.heading("size", anchor="center")
blocked_tree.tag_configure("blocked", foreground=theme[6])
blocked_tree.pack(fill="x", padx=12, pady=(0, 12))

#------------------------------------------------------------


panel = tk.Frame(
    window_r,
    bg=theme[1],
    highlightbackground=theme[7],
    highlightthickness=1,
)
panel.pack(fill="both", expand=True, padx=22, pady=(0, 20))
panel.grid_rowconfigure(1, weight=1)
panel.grid_columnconfigure(0, weight=1)


filters = tk.Frame(panel, bg=theme[1])
filters.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
filters.grid_columnconfigure(7, weight=1)

tk.Label(
    filters, text="Protocol", bg=theme[1], fg=theme[4],
    font=("Segoe UI", 10),
).grid(row=0, column=0, padx=(0, 7))

protocol_var = tk.StringVar(value="All")
protocol_box = ttk.Combobox(
    filters,
    textvariable=protocol_var,
    values=("All", "TCP", "UDP", "ARP", "ICMP"),
    state="readonly",
    width=10,
)
protocol_box.grid(row=0, column=1, padx=(0, 14))
protocol_box.bind("<<ComboboxSelected>>", lambda event: show_records())

tk.Label(
    filters, text="Status", bg=theme[1], fg=theme[4],
    font=("Segoe UI", 10),
).grid(row=0, column=2, padx=(0, 7))

status_var = tk.StringVar(value="All")
status_box = ttk.Combobox(
    filters,
    textvariable=status_var,
    values=("All", "Allowed", "Blocked"),
    state="readonly",
    width=14,
)
status_box.grid(row=0, column=3, padx=(0, 14))
status_box.bind("<<ComboboxSelected>>", lambda event: show_records())

tk.Label(
    filters, text="Service", bg=theme[1], fg=theme[4],
    font=("Segoe UI", 10),
).grid(row=0, column=4, padx=(0, 7))

service_var = tk.StringVar(value="All")
service_values = ("All", *sorted(set(PORT_NAMES.values())), "Unknown")

service_box = ttk.Combobox(
    filters,
    textvariable=service_var,
    values=service_values,
    state="readonly",
    width=13,
)
service_box.grid(row=0, column=5, padx=(0, 14))
service_box.bind("<<ComboboxSelected>>", lambda event: show_records())

tk.Label(
    filters, text="Search", bg=theme[1], fg=theme[4],
    font=("Segoe UI", 10),
).grid(row=0, column=6, padx=(0, 7))

#------------------------------------------------------------

search_var = tk.StringVar()

search_entry = tk.Entry(
    filters,
    textvariable=search_var,
    bg=theme[0],
    fg=theme[3],
    insertbackground=theme[3],
    relief="flat",
    highlightbackground=theme[7],
    highlightcolor=theme[7],
    highlightthickness=1,
    font=("Segoe UI", 10),
)
search_entry.grid(row=0, column=7, sticky="ew", ipady=8, padx=(0, 8))
search_var.trace_add("write", lambda *_: show_records())

tk.Button(
    filters,
    text="Clear",
    command=clear_search,
    bg=theme[2],
    fg=theme[3],
    activebackground=theme[9],
    activeforeground=theme[3],
    relief="flat",
    padx=12,
    pady=7,
    cursor="hand2",
).grid(row=0, column=8)

#------------------------------------------------------------

table_frame = tk.Frame(panel, bg=theme[1])
table_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
table_frame.grid_rowconfigure(0, weight=1)
table_frame.grid_columnconfigure(0, weight=1)

columns = (
    "time", "proto", "src", "dst",
    "service", "domain", "size", "status",
)

tree = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings",
)

column_info = {
    "time": ("Time", 85),
    "proto": ("Protocol", 85),
    "src": ("Source", 180),
    "dst": ("Destination", 180),
    "service": ("Service", 100),
    "domain": ("Domain", 200),
    "size": ("Size", 80),
    "status": ("Status", 130),
}

for key, (heading, width) in column_info.items():
    tree.heading(key, text=heading)
    tree.column(key, width=width, minwidth=65, anchor="w")

tree.column("size", anchor="center")
tree.heading("size", anchor="center")

tree.tag_configure("allowed", foreground=theme[5])
tree.tag_configure("blocked", foreground=theme[6])

scrollbar = ttk.Scrollbar(
    table_frame,
    orient="vertical",
    command=tree.yview,
)
tree.configure(yscrollcommand=scrollbar.set)

tree.grid(row=0, column=0, sticky="nsew")
scrollbar.grid(row=0, column=1, sticky="ns")

PP26.start_sniffing()
poll_queue()
window_r.mainloop()