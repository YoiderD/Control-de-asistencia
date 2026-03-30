import threading
import time
import os
import sys
import webview
from asistencia.app import app

def resource_path(relative_path):
    """ Obtiene la ruta absoluta para recursos, funciona para dev y para PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def start_flask():
    # Importante: Flask necesita saber dónde están sus carpetas dentro del EXE
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    time.sleep(2)

    webview.create_window(
        "Sistema de Asistencia - Colegio",
        "http://127.0.0.1:5000/",
        width=1100,
        height=750,
        resizable=True
    )

    webview.start()