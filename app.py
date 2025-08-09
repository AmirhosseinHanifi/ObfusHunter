import sys, joblib, psutil, numpy as np
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel
from pytorch_tabnet.tab_model import TabNetClassifier

FEATURE_DIM = 8  # باید مطابق آموزش مدل شما باشد

def safe_int(x, default=0):
    try: return int(x)
    except: return default

class ScanWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal(int)

    def __init__(self, model_path="tabnet_model.zip", scaler_path="scaler.pkl", parent=None):
        super().__init__(parent)
        self.model = TabNetClassifier(); self.model.load_model(model_path)
        try: self.scaler = joblib.load(scaler_path)
        except: self.scaler = None

    def extract_features(self, proc):
        try:
            with proc.oneshot():
                cpu = proc.cpu_percent(interval=0.0)
                mem = proc.memory_percent()
                thr = safe_int(proc.num_threads())
                ctx = proc.num_ctx_switches()
                ctx_sum = safe_int(getattr(ctx, "voluntary", 0)) + safe_int(getattr(ctx, "involuntary", 0))
                io = None
                try: io = proc.io_counters()
                except: pass
                rb = safe_int(getattr(io, "read_bytes", 0))
                wb = safe_int(getattr(io, "write_bytes", 0))
                try: ofc = len(proc.open_files())
                except: ofc = 0
                try: conns = len(proc.connections(kind="inet"))  # در psutil جدید deprecated است، فعلاً قابل‌قبول
                except: conns = 0
                return [cpu, mem, thr, ctx_sum, rb, wb, ofc, conns]
        except:  # AccessDenied, Zombie, ...
            return None

    def run(self):
        rows, metas = [], []
        self.line.emit("⚙️ Scanning processes...\n")
        for proc in psutil.process_iter(["pid", "name"]):
            feats = self.extract_features(proc)
            if feats and len(feats) == FEATURE_DIM:
                rows.append(feats)
                metas.append((proc.info.get("pid"), proc.info.get("name")))
        if not rows:
            self.line.emit("No accessible processes.")
            self.done.emit(0); return

        X = np.asarray(rows, dtype=np.float32)
        if self.scaler is not None:
            try: X = self.scaler.transform(X).astype(np.float32)
            except: self.line.emit("⚠️ scaler transform failed; using raw features.\n")

        # TabNet predict: لیبل (np.ndarray)
        preds = self.model.predict(X)
        total, mal = len(preds), 0
        for (pid, name), y in zip(metas, preds):
            if int(y) == 1:
                mal += 1
                self.line.emit(f"⚠️ Malware suspected: PID={pid} | {name}")
        self.line.emit(f"\n✅ Done. {mal}/{total} flagged.")
        self.done.emit(mal)

class MalwareScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ObfusHunter — Real-Time RAM Scanner")
        self.setGeometry(100, 100, 760, 520)
        v = QVBoxLayout(self)
        self.label = QLabel("🔍 Click to scan running processes (non-blocking).")
        self.text  = QTextEdit(); self.text.setReadOnly(True)
        self.btn   = QPushButton("Start Scan"); self.btn.clicked.connect(self.start_scan)
        v.addWidget(self.label); v.addWidget(self.btn); v.addWidget(self.text)
        self.worker = None

    def start_scan(self):
        self.text.clear(); self.btn.setEnabled(False)
        self.worker = ScanWorker()
        self.worker.line.connect(self.text.append)
        self.worker.done.connect(lambda _: self.btn.setEnabled(True))
        self.worker.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MalwareScanner(); w.show()
    sys.exit(app.exec_())
