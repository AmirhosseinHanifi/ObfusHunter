import sys
import torch
import joblib
import psutil
import numpy as np
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel
from pytorch_tabnet.tab_model import TabNetClassifier
from sklearn.preprocessing import StandardScaler

class MalwareScanner(QWidget):
    def init(self):
        super().init()
        self.setWindowTitle("Real-Time Malware RAM Scanner")
        self.setGeometry(100, 100, 600, 400)
        layout = QVBoxLayout()

        self.label = QLabel("🔍 Click to start scanning RAM processes.")
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.button = QPushButton("Start Scan")
        self.button.clicked.connect(self.scan)

        layout.addWidget(self.label)
        layout.addWidget(self.button)
        layout.addWidget(self.text)
        self.setLayout(layout)

        # Load model and scaler
        self.model = TabNetClassifier()
        self.model.load_model("tabnet_model.zip")
        self.scaler = joblib.load("scaler.pkl")

    def extract_features(self, proc):
        try:
            with proc.oneshot():
                return [
                    proc.cpu_percent(interval=0.1),
                    proc.memory_percent(),
                    proc.num_threads(),
                    proc.num_ctx_switches().voluntary + proc.num_ctx_switches().involuntary,
                    proc.io_counters().read_bytes,
                    proc.io_counters().write_bytes,
                    len(proc.open_files()),
                    len(proc.connections())
                ]
        except Exception:
            return None

    def scan(self):
        self.text.clear()
        self.text.append("⚙️ Scanning started...\n")
        for proc in psutil.process_iter():
            features = self.extract_features(proc)
            if features:
                X = self.scaler.transform([features]).astype(np.float32)
                pred = self.model.predict(X)[0]
                if pred == 1:
                    self.text.append(f"⚠️ Malware Detected: PID={proc.pid}, Name={proc.name()}")
                else:
                    self.text.append(f"✅ Safe: PID={proc.pid}, Name={proc.name()}")

if name == "main":
    app = QApplication(sys.argv)
    window = MalwareScanner()
    window.show()
    sys.exit(app.exec_())
