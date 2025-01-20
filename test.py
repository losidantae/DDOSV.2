import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import threading
import datetime
import csv
from collections import Counter
from scapy.all import sniff
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# -----------------------
# Color Theme (ปรับได้ตามชอบ)
# -----------------------
BACKGROUND = "#2C3E50"    # สีพื้นหลังหลัก (เข้ม)
FOREGROUND = "#ECF0F1"    # สีตัวอักษร (อ่อน/ขาว)
ACCENT = "#3498DB"        # สีปุ่มหรือแถบเมนู
HIGHLIGHT = "#E74C3C"     # สีเน้น (เช่นสีแดง)

# -----------------------
# Global Variables
# -----------------------
packet_counts = Counter()
monitored_ips = []
TIME_WINDOW = 10
THRESHOLD = 1000
stop_flag = False

# -----------------------
# ฟังก์ชันช่วยประมวลผล
# -----------------------
def calculate_risk_level(packet_count):
    if packet_count > THRESHOLD * 1.5:
        return "High"
    elif packet_count > THRESHOLD:
        return "Medium"
    else:
        return "Low"

# -----------------------
# ฟังก์ชันสร้างกราฟวงกลม
# -----------------------
def plot_pie_chart(frame, traffic_data):
    high = sum(1 for c in traffic_data if c > THRESHOLD * 1.5)
    med = sum(1 for c in traffic_data if THRESHOLD < c <= THRESHOLD * 1.5)
    low = sum(1 for c in traffic_data if c <= THRESHOLD)

    total = high + med + low
    if total == 0:
        sizes = [0, 0, 100]
    else:
        sizes = [(high/total)*100, (med/total)*100, (low/total)*100]

    labels = ['High', 'Medium', 'Low']
    colors = [HIGHLIGHT, "#f1c40f", "#27ae60"]  # แดง, เหลือง, เขียว
    explode = (0.1, 0, 0)

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(sizes, explode=explode, labels=labels, colors=colors,
           autopct='%1.1f%%', startangle=90)
    ax.axis('equal')

    # ล้าง widget เก่าก่อนวาดใหม่
    for w in frame.winfo_children():
        w.destroy()

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack()

# -----------------------
# ฟังก์ชันสร้างกราฟแท่ง (Bar Chart) สำหรับหน้า Home / Reporting
# -----------------------
def plot_bar_chart_home(frame, top_ip_data):
    """
    ใช้ในหน้า Home แสดง top_ip_data = [(ip, count), ...]
    """
    for w in frame.winfo_children():
        w.destroy()

    if not top_ip_data:
        tk.Label(frame, text="No traffic data to display.",
                 fg=FOREGROUND, bg=BACKGROUND, font=("Arial", 12)).pack()
        return

    ips = [ip for (ip, _) in top_ip_data]
    counts = [count for (_, count) in top_ip_data]

    fig, ax = plt.subplots(figsize=(4, 3))
    ax.bar(ips, counts, color="#f39c12")
    ax.set_xlabel('IP Address')
    ax.set_ylabel('Packets')
    ax.set_title('Top IP Traffic')

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack()

def plot_bar_chart_reporting(frame, ip_list, packet_list):
    """
    ใช้ในหน้า Reporting แสดงรายการ IP ทั้งหมด
    """
    for w in frame.winfo_children():
        w.destroy()

    if not ip_list:
        tk.Label(frame, text="No data for Bar Chart",
                 bg=BACKGROUND, fg=FOREGROUND).pack()
        return

    fig, ax = plt.subplots(figsize=(4,3))
    ax.bar(ip_list, packet_list, color="#9b59b6")
    ax.set_title("Reporting Bar Chart")
    ax.set_xlabel("IP Address")
    ax.set_ylabel("Packets")

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack()


# -----------------------
# GUI หลัก
# -----------------------
root = tk.Tk()
root.title("DDos Detect AI")
root.geometry("900x600")
root.configure(bg=BACKGROUND)

# -----------------------
# Navigation
# -----------------------
def show_frame(frame):
    for w in root.winfo_children():
        w.pack_forget()
    menu_frame.pack(fill="x")
    frame.pack(fill="both", expand=True)

menu_frame = tk.Frame(root, bg=ACCENT)

# -----------------------
# Packet Sniffing
# -----------------------
def monitor_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        if src_ip in monitored_ips:
            packet_counts[src_ip] += 1

# -----------------------
# หน้า Home
# -----------------------
def create_home_page():
    home_frame = tk.Frame(root, bg=BACKGROUND)
    tk.Label(home_frame, text="Home Page", font=("Arial", 24, "bold"),
             fg=FOREGROUND, bg=BACKGROUND).pack(pady=10)

    # ---- Pie Chart ด้านบน ----
    pie_chart_frame = tk.Frame(home_frame, bg=BACKGROUND)
    pie_chart_frame.pack(pady=10)
    plot_pie_chart(pie_chart_frame, [0])  # เริ่มแรกยังไม่มีข้อมูล

    # ---- ส่วนแสดงสถิติ + เวลา ----
    status_frame = tk.Frame(home_frame, bg=BACKGROUND)
    status_frame.pack(pady=5)

    system_label = tk.Label(status_frame, text="System is running...",
                            fg=FOREGROUND, bg=BACKGROUND, font=("Arial", 12))
    system_label.grid(row=0, column=0, sticky="w", padx=10, pady=2)

    monitored_label = tk.Label(status_frame, text="Monitoring IPs: 0",
                               fg=FOREGROUND, bg=BACKGROUND, font=("Arial", 12))
    monitored_label.grid(row=1, column=0, sticky="w", padx=10, pady=2)

    packet_label = tk.Label(status_frame, text="Total Packets: 0",
                            fg=FOREGROUND, bg=BACKGROUND, font=("Arial", 12))
    packet_label.grid(row=2, column=0, sticky="w", padx=10, pady=2)

    time_label = tk.Label(status_frame, text="Time: --:--:--",
                          fg=FOREGROUND, bg=BACKGROUND, font=("Arial", 12))
    time_label.grid(row=3, column=0, sticky="w", padx=10, pady=2)

    def update_time_label():
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        time_label.config(text=f"Time: {now_str}")
        time_label.after(1000, update_time_label)
    update_time_label()

    # ---- ส่วนแสดง Bar Chart + Top 5 IP Traffic ----
    bottom_frame = tk.Frame(home_frame, bg=BACKGROUND)
    bottom_frame.pack(fill="x", expand=False, padx=10, pady=10)

    left_bottom_frame = tk.Frame(bottom_frame, bg=BACKGROUND)
    left_bottom_frame.pack(side=tk.LEFT, fill="y")

    tk.Label(left_bottom_frame, text="Top 5 IP Traffic",
             bg=BACKGROUND, fg=FOREGROUND,
             font=("Arial", 14, "bold")).pack(anchor="w")

    top_ip_box = tk.Text(left_bottom_frame, width=35, height=12,
                         bg="#34495E", fg=FOREGROUND, font=("Arial", 11))
    top_ip_box.pack(pady=5)

    right_bottom_frame = tk.Frame(bottom_frame, bg=BACKGROUND)
    right_bottom_frame.pack(side=tk.LEFT, fill="both", expand=True)

    def refresh_home():
        # อัปเดตจำนวน IP + Packet
        num_ips = len(monitored_ips)
        monitored_label.config(text=f"Monitoring IPs: {num_ips}")

        total_packets = sum(packet_counts[ip] for ip in monitored_ips)
        packet_label.config(text=f"Total Packets: {total_packets}")

        # วาด Pie Chart
        traffic_data = [packet_counts[ip] for ip in monitored_ips]
        plot_pie_chart(pie_chart_frame, traffic_data)

        # Top IP
        if monitored_ips:
            sorted_ips = sorted(monitored_ips, key=lambda ip: packet_counts[ip], reverse=True)
            top_5 = sorted_ips[:5]
            top_ip_box.delete("1.0", tk.END)
            top_ip_data = []
            for ip in top_5:
                cnt = packet_counts[ip]
                top_ip_data.append((ip,cnt))
                top_ip_box.insert(tk.END, f"{ip} => {cnt} packets\n")
        else:
            top_ip_box.delete("1.0", tk.END)
            top_ip_box.insert(tk.END, "No IPs monitored.\n")
            top_ip_data = []

        plot_bar_chart_home(right_bottom_frame, top_ip_data)

    refresh_button = tk.Button(home_frame, text="Refresh Home",
                               bg=ACCENT, fg=FOREGROUND, font=("Arial", 12, "bold"),
                               command=refresh_home, cursor="hand2")
    refresh_button.pack(pady=10)

    return home_frame

# -----------------------
# หน้า Scan
# -----------------------
def create_scan_page():
    scan_frame = tk.Frame(root, bg=BACKGROUND)
    tk.Label(scan_frame, text="Scan Page", font=("Arial", 18, "bold"),
             fg=FOREGROUND, bg=BACKGROUND).pack(pady=10)

    ip_entry = tk.Entry(scan_frame, width=30, font=("Arial", 12))
    ip_entry.pack()

    def add_ip():
        ip = ip_entry.get()
        if ip:
            monitored_ips.append(ip)
            messagebox.showinfo("Added", f"Added IP: {ip}")
            ip_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "No IP entered")

    tk.Button(scan_frame, text="Add IP", command=add_ip,
              bg=ACCENT, fg=FOREGROUND, font=("Arial", 12),
              cursor="hand2").pack(pady=5)

    def set_threshold():
        def save_threshold():
            global THRESHOLD
            try:
                THRESHOLD = int(threshold_entry.get())
                threshold_window.destroy()
                messagebox.showinfo("Success", f"Threshold set to {THRESHOLD} packets")
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")

        threshold_window = tk.Toplevel(root)
        threshold_window.title("Set Threshold")
        threshold_window.configure(bg=BACKGROUND)
        tk.Label(threshold_window, text="Enter Threshold (packets):",
                 bg=BACKGROUND, fg=FOREGROUND).pack(pady=5)
        threshold_entry = tk.Entry(threshold_window)
        threshold_entry.pack(pady=5)
        tk.Button(threshold_window, text="Save", command=save_threshold,
                  bg=ACCENT, fg=FOREGROUND).pack(pady=5)

    def set_time_window():
        def save_time_window():
            global TIME_WINDOW
            try:
                TIME_WINDOW = int(time_window_entry.get())
                time_window_window.destroy()
                messagebox.showinfo("Success", f"Time Window set to {TIME_WINDOW} seconds")
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")

        time_window_window = tk.Toplevel(root)
        time_window_window.title("Set Time Window")
        time_window_window.configure(bg=BACKGROUND)
        tk.Label(time_window_window, text="Enter Time Window (seconds):",
                 bg=BACKGROUND, fg=FOREGROUND).pack(pady=5)
        time_window_entry = tk.Entry(time_window_window)
        time_window_entry.pack(pady=5)
        tk.Button(time_window_window, text="Save", command=save_time_window,
                  bg=ACCENT, fg=FOREGROUND).pack(pady=5)

    tk.Button(scan_frame, text="Set Threshold", bg=ACCENT, fg=FOREGROUND,
              font=("Arial", 12), command=set_threshold, cursor="hand2").pack(pady=5)

    tk.Button(scan_frame, text="Set Time Window", bg=ACCENT, fg=FOREGROUND,
              font=("Arial", 12), command=set_time_window, cursor="hand2").pack(pady=5)

    output_box = tk.Text(scan_frame, width=60, height=10, font=("Arial", 12),
                         bg="#34495E", fg=FOREGROUND)
    output_box.pack(pady=10)

    def update_scan_output():
        output_box.delete("1.0", tk.END)
        if monitored_ips:
            output_box.insert(tk.END, "Monitored IPs:\n")
            for ip in monitored_ips:
                output_box.insert(tk.END, f"{ip} => {packet_counts[ip]}\n")
        else:
            output_box.insert(tk.END, "No IPs monitored.\n")

    def sniff_loop():
        while True:
            if stop_flag:
                break
            sniff(prn=monitor_packet, store=0, timeout=TIME_WINDOW)
            update_scan_output()

    def start_scan():
        global stop_flag
        stop_flag = False
        sniff_thread = threading.Thread(target=sniff_loop)
        sniff_thread.daemon = True
        sniff_thread.start()

    def stop_scan():
        global stop_flag
        stop_flag = True
        messagebox.showinfo("Stopped", "Scanning Stopped")

    tk.Button(scan_frame, text="Start Scan", bg="#27ae60", fg=FOREGROUND,
              font=("Arial", 12), command=start_scan, cursor="hand2").pack(pady=5)

    tk.Button(scan_frame, text="Stop Scan", bg=HIGHLIGHT, fg=FOREGROUND,
              font=("Arial", 12), command=stop_scan, cursor="hand2").pack(pady=5)

    return scan_frame

# -----------------------
# หน้า Traffic Summary
# -----------------------
def update_traffic_summary(listbox, table, chart_frame):
    # ล้างข้อมูลเก่า
    listbox.delete(0, tk.END)
    for item in table.get_children():
        table.delete(item)
    
    traffic_data = []
    high_ips = []
    med_ips = []
    low_ips = []

    for ip in monitored_ips:
        count = packet_counts[ip]
        risk = calculate_risk_level(count)
        status = "Blocked" if risk == "High" else "Active"

        traffic_data.append(count)
        if risk == "High":
            high_ips.append(ip)
        elif risk == "Medium":
            med_ips.append(ip)
        else:
            low_ips.append(ip)

        table.insert("", "end", values=(ip, count, risk, status))

    # ใส่ใน listbox ตามลำดับ
    for ip in high_ips + med_ips + low_ips:
        listbox.insert(tk.END, ip)

    # อัปเดตกราฟวงกลม
    plot_pie_chart(chart_frame, traffic_data)

def create_traffic_summary_page():
    traffic_frame = tk.Frame(root, bg=BACKGROUND)
    tk.Label(traffic_frame, text="Traffic Summary", font=("Arial", 18, "bold"),
             fg=FOREGROUND, bg=BACKGROUND).pack(pady=10)

    top_frame = tk.Frame(traffic_frame, bg=BACKGROUND)
    top_frame.pack(fill="x", pady=10)

    left_frame = tk.Frame(top_frame, bg=BACKGROUND)
    left_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(left_frame, text="IP Listbox", bg=BACKGROUND, fg=FOREGROUND,
             font=("Arial", 12, "bold")).pack()

    listbox = tk.Listbox(left_frame, height=10, bg="#34495E", fg=FOREGROUND,
                         font=("Arial", 12))
    listbox.pack()

    def block_ip():
        ip = listbox.get(tk.ACTIVE)
        if ip:
            if ip in packet_counts:
                del packet_counts[ip]
            listbox.delete(tk.ACTIVE)
            messagebox.showinfo("Blocked", f"Blocked IP: {ip}")
        else:
            messagebox.showwarning("No IP", "No IP selected")

    tk.Button(left_frame, text="Block IP", command=block_ip,
              bg=HIGHLIGHT, fg=FOREGROUND, font=("Arial", 12),
              cursor="hand2").pack(pady=5)

    def refresh():
        update_traffic_summary(listbox, table, chart_frame)

    tk.Button(left_frame, text="Refresh", command=refresh,
              bg=ACCENT, fg=FOREGROUND, font=("Arial", 12),
              cursor="hand2").pack(pady=5)

    right_frame = tk.Frame(top_frame, bg=BACKGROUND)
    right_frame.pack(side=tk.LEFT, fill="both", expand=True)

    chart_frame = tk.Frame(right_frame, bg=BACKGROUND, height=200)
    chart_frame.pack(fill="both", expand=True, padx=10, pady=10)

    bottom_frame = tk.Frame(traffic_frame, bg=BACKGROUND)
    bottom_frame.pack(fill="both", expand=True, padx=10, pady=10)

    columns = ("IP Address", "Packets", "Risk", "Status")
    table = ttk.Treeview(bottom_frame, columns=columns, show="headings", height=8)
    table.pack(fill="both", expand=True)

    for col in columns:
        table.heading(col, text=col)

    refresh()
    return traffic_frame

# -----------------------
# หน้า Reporting (ลบ old/full ออก เหลือฟังก์ชันเดียว: refresh_reporting)
# -----------------------
def create_reporting_page():
    reporting_frame = tk.Frame(root, bg=BACKGROUND)
    tk.Label(reporting_frame, text="Reporting Page", font=("Arial", 18, "bold"),
             fg=FOREGROUND, bg=BACKGROUND).pack(pady=10)

    # ตาราง
    table_frame = tk.Frame(reporting_frame, bg=BACKGROUND)
    table_frame.pack(fill="both", expand=True, padx=10, pady=5)

    columns = ("IP Address", "Packets", "Risk", "Status")
    report_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
    report_table.pack(fill="both", expand=True)

    for col in columns:
        report_table.heading(col, text=col)

    # Pie Chart
    chart_frame = tk.Frame(reporting_frame, bg=BACKGROUND, height=200)
    chart_frame.pack(fill="x", expand=False, padx=10, pady=10)

    refresh_btn = tk.Button(reporting_frame, text="Refresh Reporting",
                            bg=ACCENT, fg=FOREGROUND, font=("Arial", 12),
                            cursor="hand2")
    refresh_btn.pack(pady=5)

    # Summary Boxes
    summary_frame = tk.Frame(reporting_frame, bg=BACKGROUND)
    summary_frame.pack(fill="x", padx=10, pady=5)

    lbl_high = tk.Label(summary_frame, text="High Risk IPs: 0",
                        bg=BACKGROUND, fg=FOREGROUND, font=("Arial", 10, "bold"))
    lbl_high.grid(row=0, column=0, padx=10)

    lbl_med = tk.Label(summary_frame, text="Medium Risk IPs: 0",
                       bg=BACKGROUND, fg=FOREGROUND, font=("Arial", 10, "bold"))
    lbl_med.grid(row=0, column=1, padx=10)

    lbl_low = tk.Label(summary_frame, text="Low Risk IPs: 0",
                       bg=BACKGROUND, fg=FOREGROUND, font=("Arial", 10, "bold"))
    lbl_low.grid(row=0, column=2, padx=10)

    lbl_blocked = tk.Label(summary_frame, text="Blocked IPs: 0",
                           bg=BACKGROUND, fg=FOREGROUND, font=("Arial", 10, "bold"))
    lbl_blocked.grid(row=0, column=3, padx=10)

    # Export CSV
    def export_csv():
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV Files","*.csv"),("All Files","*.*")])
        if file_path:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address","Packets","Risk","Status"])
                for item in report_table.get_children():
                    vals = report_table.item(item, "values")
                    writer.writerow(vals)
            messagebox.showinfo("Export CSV", f"Exported to {file_path}")

    export_btn = tk.Button(summary_frame, text="Export CSV", bg=ACCENT, fg=FOREGROUND,
                           cursor="hand2", command=export_csv)
    export_btn.grid(row=0, column=4, padx=10)

    # Additional Bar Chart
    add_chart_frame = tk.Frame(reporting_frame, bg=BACKGROUND, height=200)
    add_chart_frame.pack(fill="x", padx=10, pady=5)

    # Filter/Search
    filter_frame = tk.Frame(reporting_frame, bg=BACKGROUND)
    filter_frame.pack(fill="x", padx=10, pady=5, anchor="w")

    tk.Label(filter_frame, text="Search IP:", bg=BACKGROUND, fg=FOREGROUND).pack(side="left", padx=5)
    search_var = tk.StringVar()
    search_entry = tk.Entry(filter_frame, textvariable=search_var, width=20)
    search_entry.pack(side="left", padx=5)

    def filter_table():
        query = search_var.get().strip()
        for item in report_table.get_children():
            report_table.delete(item)
        traffic_data_temp = []
        for ip in monitored_ips:
            if query in ip:
                count = packet_counts[ip]
                risk = calculate_risk_level(count)
                status = "Blocked" if risk == "High" else "Active"
                report_table.insert("", "end", values=(ip, count, risk, status))
                traffic_data_temp.append(count)
        plot_pie_chart(chart_frame, traffic_data_temp)

    tk.Button(filter_frame, text="Filter", bg=ACCENT, fg=FOREGROUND,
              command=filter_table, cursor="hand2").pack(side="left")

    # Notifications/Alerts
    alert_label = tk.Label(reporting_frame, text="", bg=BACKGROUND, fg=HIGHLIGHT,
                           font=("Arial", 12, "bold"))
    alert_label.pack(pady=2)

    # Additional Insights
    insight_frame = tk.Frame(reporting_frame, bg=BACKGROUND)
    insight_frame.pack(fill="x", padx=10, pady=5)

    lbl_average = tk.Label(insight_frame, text="Average Packets/IP: 0",
                           bg=BACKGROUND, fg=FOREGROUND)
    lbl_average.grid(row=0, column=0, padx=10)

    lbl_highest = tk.Label(insight_frame, text="Highest Packet Count: 0",
                           bg=BACKGROUND, fg=FOREGROUND)
    lbl_highest.grid(row=0, column=1, padx=10)

    # ========= ฟังก์ชัน refresh_reporting (ฟังก์ชันเดียว) =========
    def refresh_reporting():
        # 1) ล้างตาราง
        for item in report_table.get_children():
            report_table.delete(item)

        # 2) ใส่ข้อมูลตาราง
        traffic_data = []
        for ip in monitored_ips:
            count = packet_counts[ip]
            risk = calculate_risk_level(count)
            status = "Blocked" if risk == "High" else "Active"
            report_table.insert("", "end", values=(ip, count, risk, status))
            traffic_data.append(count)

        # 3) วาด Pie Chart
        plot_pie_chart(chart_frame, traffic_data)

        # 4) Summary Boxes
        high_count = sum(1 for ip in monitored_ips if calculate_risk_level(packet_counts[ip]) == "High")
        med_count  = sum(1 for ip in monitored_ips if calculate_risk_level(packet_counts[ip]) == "Medium")
        low_count  = sum(1 for ip in monitored_ips if calculate_risk_level(packet_counts[ip]) == "Low")
        blocked_count = high_count  # สมมติถือว่า High = Blocked

        lbl_high.config(text=f"High Risk IPs: {high_count}")
        lbl_med.config(text=f"Medium Risk IPs: {med_count}")
        lbl_low.config(text=f"Low Risk IPs: {low_count}")
        lbl_blocked.config(text=f"Blocked IPs: {blocked_count}")

        # 5) Alerts
        if high_count > 0:
            alert_label.config(text=f"Alert! Found {high_count} High Risk IP(s).")
        else:
            alert_label.config(text="")

        # 6) Insights
        if len(monitored_ips) > 0:
            avg_pkt = sum(traffic_data)/len(monitored_ips)
        else:
            avg_pkt = 0
        lbl_average.config(text=f"Average Packets/IP: {avg_pkt:.2f}")

        highest_pkt = max(traffic_data) if traffic_data else 0
        lbl_highest.config(text=f"Highest Packet Count: {highest_pkt}")

        # 7) Bar Chart
        ip_list = monitored_ips.copy()
        packet_list = [packet_counts[ip] for ip in ip_list]
        plot_bar_chart_reporting(add_chart_frame, ip_list, packet_list)

    refresh_btn.config(command=refresh_reporting)
    refresh_reporting()

    return reporting_frame


# -----------------------
# สร้างหน้า
# -----------------------
home_page = create_home_page()
scan_page = create_scan_page()
traffic_summary_page = create_traffic_summary_page()
reporting_page = create_reporting_page()

# -----------------------
# สร้างปุ่มเมนู (Navigation) บน menu_frame
# -----------------------
btn_font = ("Arial", 12, "bold")

home_btn = tk.Button(menu_frame, text="Home", fg=FOREGROUND, bg=ACCENT,
                     font=btn_font, cursor="hand2",
                     command=lambda: show_frame(home_page))
home_btn.pack(side="left", padx=5)

scan_btn = tk.Button(menu_frame, text="Scan", fg=FOREGROUND, bg=ACCENT,
                     font=btn_font, cursor="hand2",
                     command=lambda: show_frame(scan_page))
scan_btn.pack(side="left", padx=5)

ts_btn = tk.Button(menu_frame, text="Traffic Summary", fg=FOREGROUND, bg=ACCENT,
                   font=btn_font, cursor="hand2",
                   command=lambda: show_frame(traffic_summary_page))
ts_btn.pack(side="left", padx=5)

report_btn = tk.Button(menu_frame, text="Reporting", fg=FOREGROUND, bg=ACCENT,
                       font=btn_font, cursor="hand2",
                       command=lambda: show_frame(reporting_page))
report_btn.pack(side="left", padx=5)

menu_frame.pack(fill="x")
show_frame(home_page)

root.mainloop()
