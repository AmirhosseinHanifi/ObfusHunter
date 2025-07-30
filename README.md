# 🛡️ ObfusHunter

**ObfusHunter** is a real-time memory monitoring tool designed to detect obfuscated malware using a trained deep learning model (TabNet). The tool is built with PyTorch, PyQt5 for GUI, and scans system memory in real-time, flagging suspicious patterns and optionally terminating malicious processes.

---

## 🚀 Features

- 🧠 Deep Learning-based malware detection (TabNet)
- ⚙️ Real-time RAM monitoring
- 🐍 Built with Python, PyQt5, and psutil
- 💾 Loads pre-trained TabNet model
- 🔥 Detects evasive obfuscated malware in memory
- ⛔ Option to kill detected malware processes

---

## 🗂️ Project Structure

```
ObfusHunter/
│
├── app.py                   # Main PyQt5 GUI and logic
├── requirements.txt         # Python dependencies
├── tabnet_model.zip         # Trained TabNet model
├── Obfuscated-MalMem2022.csv# Dataset (optional, for retraining or testing)
├── Train_model.ipynb        # Notebook used to train the TabNet model
└── README.md                # This file
```

---

## 🧰 Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## 🧠 Model

The deep learning model is trained on the [Obfuscated-MalMem2022](https://www.kaggle.com/datasets/teslacoil/obfuscated-malmem2022) dataset using TabNet for tabular malware classification. You can retrain or fine-tune using `Train_model.ipynb`.

---

## 🖥️ Usage

Run the GUI app:

```bash
python app.py
```

The interface allows you to:

- Start/stop real-time memory monitoring.
- View predictions for running processes.
- Terminate detected malicious processes.

---

## 📦 Deployment

For standalone packaging:

```bash
pyinstaller --onefile --windowed app.py
```

---

## 📊 Dataset

- **Obfuscated-MalMem2022**  
  - 100,000+ samples of memory dumps
  - Binary classification: benign vs obfuscated malware
  - Preprocessed using label encoding and standardization

---

## ✍️ Author

**Amirhossein**  
For research, academic use, or collaboration, feel free to contact.

---

## ⚠️ Disclaimer

> This tool is for **educational and research purposes only**. It is not intended for production use in high-risk environments. Always validate and test before deployment.

---

## 📘 License

MIT License
