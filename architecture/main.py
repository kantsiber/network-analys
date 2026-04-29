import sys
import os
import pyshark
import threading
import time
import collections
import joblib
import numpy as np
import asyncio
import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'Model', 'models_final', 'lightgbm_model.pkl')
TSHARK_PATH = r'D:\Wireshark\tshark.exe'
INTERFACE_NAME = 'Ethernet'

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from all_rust import NetworkFeatureExtractor
except ImportError:
    print("ОШИБКА: Файл all_rust.py не найден рядом с main.py!")
    sys.exit()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LoRaIDSApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LoRa Network IDS Monitor")
        self.geometry("1100x850")

        self.extractor = NetworkFeatureExtractor()
        self.data_points = collections.deque([0] * 50, maxlen=50)
        self.packet_count = 0
        self.is_running = True

        try:
            if os.path.exists(MODEL_PATH):
                self.model = joblib.load(MODEL_PATH)
                print(f"Модель успешно загружена: {MODEL_PATH}")
            else:
                self.model = None
                print(f"ВНИМАНИЕ: Файл модели не найден: {MODEL_PATH}")
        except Exception as e:
            self.model = None
            print(f"ОШИБКА ЗАГРУЗКИ МОДЕЛИ: {e}")

        self.setup_ui()

        self.capture_thread = threading.Thread(target=self.start_monitoring, daemon=True)
        self.capture_thread.start()

        self.update_plot()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.status_frame = ctk.CTkFrame(self, height=100)
        self.status_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")

        self.label_status = ctk.CTkLabel(self.status_frame, text="СТАТУС: ИНИЦИАЛИЗАЦИЯ...",
                                         font=("Roboto", 24, "bold"), text_color="cyan")
        self.label_status.pack(pady=20)

        self.fig = Figure(figsize=(5, 3), dpi=100, facecolor='#1a1a1a')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#1a1a1a')
        self.ax.tick_params(colors='white')
        self.line, = self.ax.plot(range(50), self.data_points, color='#00ff00', linewidth=2)
        self.ax.set_ylim(0, 50)

        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().grid(row=1, column=0, padx=20, pady=10, sticky="nsew")

        self.log_box = ctk.CTkTextbox(self, height=250, font=("Consolas", 12))
        self.log_box.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

    def start_monitoring(self):
        """Фоновый захват пакетов через конкретный интерфейс"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            if not os.path.exists(TSHARK_PATH):
                self.after(0, lambda: self.log_box.insert("0.0", f"ОШИБКА: TShark не найден: {TSHARK_PATH}\n"))
                return

            capture = pyshark.LiveCapture(
                interface=INTERFACE_NAME,
                tshark_path=TSHARK_PATH
            )

            self.after(0, lambda: self.label_status.configure(text="СИСТЕМА АКТИВНА", text_color="#00ff00"))

            for packet in capture.sniff_continuously():
                if not self.is_running:
                    break

                self.packet_count += 1

                features_dict = self.extractor.process_packet(packet)

                if features_dict is not None and self.model is not None:
                    ordered_features = self.extractor.get_features_as_ordered_array(features_dict)
                    prediction = self.model.predict(ordered_features.reshape(1, -1))

                    if prediction[0] == 1:
                        self.after(0, self.trigger_alert)
                    else:
                        t = time.strftime('%H:%M:%S')
                        msg = f"[{t}] Поток проанализирован: Безопасно\n"
                        self.after(0, lambda m=msg: self.log_box.insert("0.0", m))

        except Exception as err:
            err_str = str(err)
            self.after(0, lambda e=err_str: self.log_box.insert("0.0", f"ОШИБКА МОНИТОРИНГА: {e}\n"))

    def trigger_alert(self):
        self.label_status.configure(text="ВНИМАНИЕ: ОБНАРУЖЕНА АТАКА!", text_color="red")
        t = time.strftime('%H:%M:%S')
        self.log_box.insert("0.0", f"!!! [{t}] ALERT: ИНТРУЗИЯ ОБНАРУЖЕНА !!!\n")

    def update_plot(self):
        if not self.is_running: return
        self.data_points.append(self.packet_count)
        self.line.set_ydata(list(self.data_points))
        curr_max = max(self.data_points)
        if curr_max > self.ax.get_ylim()[1] - 5:
            self.ax.set_ylim(0, curr_max + 20)
        self.canvas.draw()
        self.packet_count = 0
        self.after(1000, self.update_plot)

    def on_closing(self):
        self.is_running = False
        self.destroy()


if __name__ == "__main__":
    app = LoRaIDSApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()