import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import subprocess
import threading
import os
import sys
import time

CREATE_NO_WINDOW = 0x08000000
selected_infile = ""

def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def log_write(text: str):
    log_box.configure(state="normal")
    log_box.insert("end", text + "\n")
    log_box.see("end")
    log_box.configure(state="disabled")

def set_status(text: str):
    status_var.set(text)

def toggle_controls(enabled: bool):
    state = "normal" if enabled else "disabled"
    btn_select_in.config(state=state)
    btn_encrypt.config(state=state)
    btn_decrypt.config(state=state)
    entry_pass.config(state=state)
    cmb_procs.config(state="readonly" if enabled else "disabled")
    chk_show.config(state=state)
    btn_clear_log.config(state=state)
    btn_copy_log.config(state=state)

def set_running(running: bool):
    if running:
        progress.start(12)
        set_status("Çalışıyor…")
    else:
        progress.stop()
        set_status("Hazır")

def dosya_sec():
    global selected_infile
    path = filedialog.askopenfilename(
        title="Dosyayı seç",
        filetypes=[("Tüm dosyalar", "*.*")]
    )
    if path:
        selected_infile = path
        file_var.set(path)

def clear_log():
    log_box.configure(state="normal")
    log_box.delete("1.0", "end")
    log_box.configure(state="disabled")
    log_write("[INFO] Log temizlendi.")

def copy_log():
    try:
        text = log_box.get("1.0", "end-1c")
        pencere.clipboard_clear()
        pencere.clipboard_append(text)
        set_status("Log panoya kopyalandı.")
    except Exception as e:
        messagebox.showerror("Hata", f"Kopyalama hatası: {e}")

def run_mpi(mode_cmd: str):
    global selected_infile

    infile = selected_infile.strip()
    if not infile:
        messagebox.showerror("Hata", "Önce dosyayı seç.")
        return

    password = pass_var.get().strip()
    if not password:
        messagebox.showerror("Hata", "Şifre boş olamaz.")
        return

    try:
        nprocs = int(procs_var.get())
    except Exception:
        messagebox.showerror("Hata", "Proses sayısı geçersiz.")
        return

    script_path = os.path.join(app_dir(), "paralel_mpi.py")
    log_write(f"[INFO] paralel_mpi.py aranan yol: {script_path}")

    if not os.path.exists(script_path):
        messagebox.showerror(
            "Hata",
            f"paralel_mpi.py bulunamadı:\n{script_path}\n\n"
            f"Çözüm: gui_mpi.exe ile aynı klasöre paralel_mpi.py koy."
        )
        return

    py_cmd = "python" if getattr(sys, "frozen", False) else sys.executable

    cmd = [
        "mpiexec", "-n", str(nprocs),
        py_cmd, script_path,
        mode_cmd, infile, password
    ]

    if mode_cmd == "encrypt_inplace_rename":
        msg = "Bu işlem sonunda orjinal dosya silinir ve şifreli hali kalır.\nKabul ediyor musun ?"
        action_name = "Şifreleme"
    else:
        msg = "Bu işlem sonunda şifreli dosya silinir ve orijinal hali kalır.\nKabul ediyor musun ?"
        action_name = "Çözme"

    if not messagebox.askyesno("Onay", msg):
        return

    log_write("──────────────────────────────────────────────────")
    log_write("[CMD] " + " ".join(cmd))

    toggle_controls(False)
    set_running(True)

    t0 = time.perf_counter()

    def worker():
        nonlocal infile
        try:
            p = subprocess.Popen(
                cmd,
                cwd=app_dir(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=CREATE_NO_WINDOW
            )

            for line in p.stdout:
                pencere.after(0, log_write, line.rstrip("\n"))

            rc = p.wait()
            elapsed = time.perf_counter() - t0

            def finish():
                set_running(False)
                toggle_controls(True)

                log_write(f"[BİTTİ] {action_name} | ExitCode={rc} | Süre={elapsed:.3f} sn | Proses={nprocs}")

                if rc == 0:
                    if mode_cmd == "encrypt_inplace_rename":
                        new_path = infile + ".enc"
                    else:
                        new_path = infile[:-4] if infile.lower().endswith(".enc") else infile + ".dec"

                    global selected_infile
                    selected_infile = new_path
                    file_var.set(new_path)

                    messagebox.showinfo("Tamam", f"{action_name} tamamlandı.\nSüre: {elapsed:.3f} sn")
                else:
                    messagebox.showwarning("Uyarı", f"{action_name} hata ile bitti (ExitCode={rc}). Log'a bak.")

            pencere.after(0, finish)

        except FileNotFoundError:
            def fail():
                set_running(False)
                toggle_controls(True)
                log_write("[HATA] mpiexec veya python bulunamadı. MS-MPI kurulu mu? python PATH'te mi?")
            pencere.after(0, fail)

        except Exception as e:
            def fail2():
                set_running(False)
                toggle_controls(True)
                log_write(f"[HATA] {e}")
            pencere.after(0, fail2)

    threading.Thread(target=worker, daemon=True).start()


# ===================== UI =====================
pencere = tk.Tk()
pencere.title("Dosya Şifreleme")
pencere.geometry("900x560")
pencere.minsize(860, 520)
pencere.resizable(True, True)

# Tema renkleri
BG = "#0b1220"
CARD = "#0f172a"
TEXT = "#e5e7eb"
MUTED = "#94a3b8"
BORDER = "#1f2937"
BTN_BG = "#111c33"
BTN_BG_ACTIVE = "#17264a"
INPUT_BG = "#0b1020"

LOG_BG = "#070b14"
LOG_FG = "#d1d5db"
SCROLL_BG = "#0b1020"
SCROLL_ACTIVE = "#17264a"

# ---- CUSTOM TITLEBAR ----
pencere.configure(bg=BG)
pencere.overrideredirect(True)

outer = tk.Frame(pencere, bg=BG, highlightthickness=1, highlightbackground=BORDER)
outer.pack(fill="both", expand=True)

titlebar = tk.Frame(outer, bg=BG, height=44)
titlebar.pack(fill="x")

badge = tk.Label(titlebar, text="⬤", fg="#38bdf8", bg=BG, font=("Segoe UI", 18))
badge.pack(side="left", padx=(12, 10), pady=6)

title_label = tk.Label(titlebar, text="Dosya Şifreleme", bg=BG, fg=TEXT, font=("Segoe UI Semibold", 12))
title_label.pack(side="left", pady=6)

# Maximize / Restore
_is_max = False
_prev_geom = None

def toggle_maximize():
    global _is_max, _prev_geom
    try:
        if not _is_max:
            _prev_geom = pencere.geometry()
            pencere.state("zoomed")  # Windows maximize
            _is_max = True
            btn_max.config(text="❐")
        else:
            pencere.state("normal")
            if _prev_geom:
                pencere.geometry(_prev_geom)
            _is_max = False
            btn_max.config(text="□")
        pencere.overrideredirect(True)
    except Exception:
        pass

def on_map(event):
    # minimize->restore sonrası titlebar kaybolmasın
    try:
        pencere.overrideredirect(True)
    except:
        pass

pencere.bind("<Map>", on_map)

# sağ butonlar: minimize, maximize, close
btn_min = tk.Button(
    titlebar, text="—", bg=BG, fg=TEXT, bd=0,
    activebackground=BTN_BG_ACTIVE, activeforeground=TEXT,
    font=("Segoe UI", 12), width=3,
    command=lambda: pencere.iconify()
)
btn_min.pack(side="right", padx=(0, 6), pady=6)

btn_max = tk.Button(
    titlebar, text="□", bg=BG, fg=TEXT, bd=0,
    activebackground=BTN_BG_ACTIVE, activeforeground=TEXT,
    font=("Segoe UI", 11), width=3,
    command=toggle_maximize
)
btn_max.pack(side="right", padx=(0, 6), pady=6)

btn_close = tk.Button(
    titlebar, text="✕", bg=BG, fg=TEXT, bd=0,
    activebackground="#3b0a0a", activeforeground=TEXT,
    font=("Segoe UI", 12), width=3,
    command=pencere.destroy
)
btn_close.pack(side="right", padx=(0, 10), pady=6)

# sürükle taşıma
def start_move(e):
    # Tam ekranda sürüklemeyi kapat (normal davranış)
    if _is_max:
        return
    pencere._x = e.x_root
    pencere._y = e.y_root
    geom = pencere.geometry().split("+")
    pencere._win_x = int(geom[1])
    pencere._win_y = int(geom[2])

def do_move(e):
    if _is_max:
        return
    dx = e.x_root - pencere._x
    dy = e.y_root - pencere._y
    pencere.geometry(f"+{pencere._win_x + dx}+{pencere._win_y + dy}")

for w in (titlebar, title_label, badge):
    w.bind("<Button-1>", start_move)
    w.bind("<B1-Motion>", do_move)
# çift tıkla maximize
titlebar.bind("<Double-Button-1>", lambda e: toggle_maximize())
title_label.bind("<Double-Button-1>", lambda e: toggle_maximize())

# ---- ttk stil ----
style = ttk.Style()
try:
    style.theme_use("clam")
except:
    pass

style.configure("TFrame", background=BG)
style.configure("Card.TFrame", background=CARD)
style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
style.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=("Segoe UI", 9))
style.configure("TEntry", fieldbackground=INPUT_BG, foreground=TEXT)
style.configure("TCombobox", fieldbackground=INPUT_BG, background=INPUT_BG, foreground=TEXT, arrowcolor=MUTED)

pencere.option_add("*TCombobox*Listbox.background", INPUT_BG)
pencere.option_add("*TCombobox*Listbox.foreground", TEXT)
pencere.option_add("*TCombobox*Listbox.selectBackground", BTN_BG_ACTIVE)
pencere.option_add("*TCombobox*Listbox.selectForeground", TEXT)

style.configure("TCheckbutton", background=CARD, foreground=TEXT, font=("Segoe UI", 9))
style.map("TCheckbutton", background=[("active", CARD)], foreground=[("active", TEXT)])

style.configure("Soft.TButton", font=("Segoe UI Semibold", 10), padding=10, background=BTN_BG, foreground=TEXT, borderwidth=0)
style.map("Soft.TButton", background=[("active", BTN_BG_ACTIVE), ("disabled", BORDER)], foreground=[("disabled", "#6b7280")])

style.configure("Mini.TButton", font=("Segoe UI", 9), padding=(10, 6), background=BTN_BG, foreground=TEXT, borderwidth=0)
style.map("Mini.TButton", background=[("active", BTN_BG_ACTIVE)])

style.configure("TProgressbar", troughcolor=BORDER)

# ---- içerik ----
content = ttk.Frame(outer)
content.pack(fill="both", expand=True, padx=18, pady=12)

main = ttk.Frame(content)
main.pack(fill="both", expand=True)

left = ttk.Frame(main)
left.pack(side="left", fill="y", padx=(0, 12))
left.configure(width=330)
left.pack_propagate(False)

right = ttk.Frame(main)
right.pack(side="right", fill="both", expand=True)

# Sol kart: Dosya
card1 = ttk.Frame(left, style="Card.TFrame")
card1.pack(fill="x", pady=(0, 12))

tk.Label(card1, text="Dosya", bg=CARD, fg=TEXT, font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=14, pady=(14, 6))
tk.Label(card1, text="Şifrelemek/çözmek istediğin dosyayı seç.", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(0, 10))

file_var = tk.StringVar(value="(Seçilmedi)")
file_entry = ttk.Entry(card1, textvariable=file_var, state="readonly")
file_entry.pack(fill="x", padx=14, pady=(0, 10))

btn_select_in = ttk.Button(card1, text="Dosya Seç", style="Soft.TButton", command=dosya_sec)
btn_select_in.pack(fill="x", padx=14, pady=(0, 14))

# Sol kart: Ayarlar
card2 = ttk.Frame(left, style="Card.TFrame")
card2.pack(fill="x")

tk.Label(card2, text="Ayarlar", bg=CARD, fg=TEXT, font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=14, pady=(14, 10))

row = ttk.Frame(card2, style="Card.TFrame")
row.pack(fill="x", padx=14, pady=(0, 10))

tk.Label(row, text="Proses (-n):", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")

procs_var = tk.StringVar(value="8")
cmb_procs = ttk.Combobox(row, textvariable=procs_var, values=["2", "4", "8", "16"], width=6, state="readonly")
cmb_procs.pack(side="right")

tk.Label(card2, text="Şifre:", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(0, 6))

pass_var = tk.StringVar()
entry_pass = ttk.Entry(card2, textvariable=pass_var, show="•")
entry_pass.pack(fill="x", padx=14, pady=(0, 10))

show_var = tk.BooleanVar(value=False)
def toggle_show():
    entry_pass.configure(show="" if show_var.get() else "•")

chk_show = ttk.Checkbutton(card2, text="Şifreyi göster", variable=show_var, command=toggle_show)
chk_show.pack(anchor="w", padx=14, pady=(0, 12))

btn_encrypt = ttk.Button(card2, text="Şifrele", style="Soft.TButton", command=lambda: run_mpi("encrypt_inplace_rename"))
btn_encrypt.pack(fill="x", padx=14, pady=(0, 8))

btn_decrypt = ttk.Button(card2, text="Çöz", style="Soft.TButton", command=lambda: run_mpi("decrypt_inplace_rename"))
btn_decrypt.pack(fill="x", padx=14, pady=(0, 14))

# Sağ üst: progress + status + mini butonlar
top_right = ttk.Frame(right)
top_right.pack(fill="x", pady=(0, 10))

progress = ttk.Progressbar(top_right, mode="indeterminate")
progress.pack(fill="x", pady=(0, 8))

status_var = tk.StringVar(value="Hazır")
status_line = ttk.Frame(top_right)
status_line.pack(fill="x")

status_lbl = ttk.Label(status_line, textvariable=status_var)
status_lbl.pack(side="left")

btn_copy_log = ttk.Button(status_line, text="Kopyala", style="Mini.TButton", command=copy_log)
btn_copy_log.pack(side="right", padx=(8, 0))

btn_clear_log = ttk.Button(status_line, text="Temizle", style="Mini.TButton", command=clear_log)
btn_clear_log.pack(side="right")

# Sağ: log
log_frame = ttk.Frame(right)
log_frame.pack(fill="both", expand=True)

tk.Label(log_frame, text="Log", bg=BG, fg=TEXT, font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(0, 6))
log_container = tk.Frame(log_frame, bg=BG)
log_container.pack(fill="both", expand=True)

log_box = tk.Text(
    log_container,
    bg=LOG_BG,
    fg=LOG_FG,
    insertbackground=LOG_FG,
    relief="flat",
    bd=0,
    font=("Consolas", 10),
    wrap="word"
)
log_box.pack(side="left", fill="both", expand=True)

log_scroll = tk.Scrollbar(
    log_container,
    orient="vertical",
    command=log_box.yview,
    bg=SCROLL_BG,
    troughcolor=BG,
    activebackground=SCROLL_ACTIVE,
    highlightthickness=0,
    bd=0,
    width=12
)
log_scroll.pack(side="right", fill="y")

log_box.configure(yscrollcommand=log_scroll.set, state="disabled")



toggle_controls(True)
set_running(False)

pencere.mainloop()
