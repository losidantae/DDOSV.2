import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# สร้างหน้าต่าง GUI
root = tk.Tk()
root.title("AI Scan DDoS")
root.geometry("600x600")
root.configure(bg="#232276")

# สร้างส่วนหัวเมนู
menu_frame = tk.Frame(root, bg="#232276")
menu_frame.pack(fill="x", pady=10)

home_btn = tk.Button(menu_frame, text="Home", fg="white", bg="#232276", relief="flat")
home_btn.pack(side="left", padx=10)

scan_btn = tk.Button(menu_frame, text="Scan", fg="white", bg="#3B3B8A", relief="flat")
scan_btn.pack(side="left", padx=10)

traffic_summary_btn = tk.Button(menu_frame, text="Traffic summary", fg="white", bg="#232276", relief="flat")
traffic_summary_btn.pack(side="left", padx=10)

reporting_btn = tk.Button(menu_frame, text="Reporting", fg="white", bg="#232276", relief="flat")
reporting_btn.pack(side="left", padx=10)
# กรอบเนื้อหาหลัก
content_frame = tk.Frame(root, bg="white")  # กำหนดกรอบสำหรับเนื้อหาหลัก
content_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)  # ขยายกรอบให้เต็มพื้นที่

# กราฟด้านซ้าย (กราฟวงกลม)
fig1, ax1 = plt.subplots(figsize=(3, 3))  # สร้างกราฟวงกลม
data = [70, 20, 10]  # ข้อมูลสำหรับกราฟ
colors = ["green", "red", "yellow"]  # สีของกราฟ
labels = ["70%", "20%", "10%"]  # ป้ายแสดงข้อมูล
ax1.pie(data, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)  # วาดกราฟวงกลม
ax1.axis('equal')  # ทำให้กราฟวงกลมมีขนาดเท่ากันทุกด้าน

# แสดงกราฟวงกลมใน GUI
canvas1 = FigureCanvasTkAgg(fig1, master=content_frame)
canvas1.draw()  # วาดกราฟ
canvas1.get_tk_widget().pack(side=tk.LEFT, padx=20, pady=20, fill=tk.BOTH)  # วางกราฟทางซ้าย

# กราฟด้านขวา (กราฟแท่ง)
fig2, ax2 = plt.subplots(figsize=(4, 3))  # สร้างกราฟแท่ง
labels = ["14:00", "15:00", "16:00", "17:00", "18:00", "19:00", "20:00"]  # เวลาในกราฟ
values = [3, 7, 8, 10, 6, 4, 5]  # ข้อมูลของกราฟ
colors = ["green", "yellow", "purple", "pink", "cyan", "blue", "brown"]  # สีของกราฟ
ax2.bar(labels, values, color=colors)  # วาดกราฟแท่ง
ax2.set_ylabel("Level")  # กำหนดชื่อแกน Y
ax2.set_title("Traffic Analysis")  # กำหนดชื่อกราฟ

# แสดงกราฟแท่งใน GUI
canvas2 = FigureCanvasTkAgg(fig2, master=content_frame)
canvas2.draw()  # วาดกราฟ
canvas2.get_tk_widget().pack(side=tk.LEFT, padx=20, pady=20, fill=tk.BOTH)  # วางกราฟทางซ้าย

# แสดงเวลาที่ด้านล่าง
bottom_frame = tk.Frame(root, bg="white")  # กำหนดกรอบสำหรับเวลา
bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)  # วางกรอบที่ด้านล่าง

time_label = tk.Label(bottom_frame, text="17.50 AM", bg="white", fg="black", font=("Arial", 16, "bold"))
time_label.pack()  # วางป้ายเวลา

# เรียกใช้งานแอปพลิเคชัน
root.mainloop()  # เริ่มการทำงานของโปรแกรม
