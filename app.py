# app.py 
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
from encrypt import (
    load_public_key, load_private_key,
    embed_message_rsa, extract_message_rsa,
    generate_rsa_keypair, save_public_key, save_private_key
)

APP_TITLE = "STEGACRYPT — Secure Steganography (AES+RSA)"
ROOT = tk.Tk()
ROOT.title(APP_TITLE)
ROOT.geometry("1100x680")
ROOT.minsize(900, 560)

# ---------- Styling ----------
style = ttk.Style(ROOT)
try:
    style.theme_use("clam")
except:
    pass
style.configure("Header.TLabel", font=("Consolas", 18, "bold"))
style.configure("Ascii.TLabel", font=("Courier New", 10, "bold"), foreground="#FF0400")
style.configure("Dev.TLabel", font=("Segoe UI", 10, "italic"), foreground="#ff5500")
style.configure("TButton", padding=6)

ASCII_ART = '''\
  /$$$$$$   /$$                                                                             /$$    
 /$$__  $$ | $$                                                                            | $$    
| $$  \__//$$$$$$    /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$  
|  $$$$$$|_  $$_/   /$$__  $$ /$$__  $$ |____  $$ /$$_____/ /$$__  $$| $$  | $$ /$$__  $$|_  $$_/  
 \____  $$ | $$    | $$$$$$$$| $$  \ $$  /$$$$$$$| $$      | $$  \__/| $$  | $$| $$  \ $$  | $$    
 /$$  \ $$ | $$ /$$| $$_____/| $$  | $$ /$$__  $$| $$      | $$      | $$  | $$| $$  | $$  | $$ /$$
|  $$$$$$/ |  $$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$| $$$$$$$/  |  $$$$/
 \______/   \___/   \_______/ \____  $$ \_______/ \_______/|__/       \____  $$| $$____/    \___/  
                              /$$  \ $$                               /$$  | $$| $$                
                             |  $$$$$$/                              |  $$$$$$/| $$                
                              \______/                                \______/ |__/             
'''

# ---------- State ----------
input_image = ""
output_image = ""
encoded_image = ""
public_key_path = "public.pem"
private_key_path = "private.pem"

_preview_photo = None
_preview_image = None

# ---------- Helpers ----------
def set_status(s: str):
    status_var.set(s)
    ROOT.update_idletasks()

def ensure_keys_exist():
    """If public.pem/private.pem missing, generate them and save to cwd."""
    if os.path.exists(public_key_path) and os.path.exists(private_key_path):
        return False  # no generation
    priv, pub = generate_rsa_keypair()
    save_private_key(priv, private_key_path)
    save_public_key(pub, public_key_path)
    return True

def capacity_for_image(path: str) -> int:
    """Return capacity in bytes for the image (using RGBA, 1 bit per channel)."""
    img = Image.open(path).convert("RGBA")
    pixels = list(img.getdata())
    bits_capacity = len(pixels) * 4
    return bits_capacity // 8

def preview_image(path: str):
    global _preview_image, _preview_photo
    try:
        img = Image.open(path).convert("RGBA")
        _preview_image = img
        redraw_preview()
    except Exception as e:
        messagebox.showerror("Preview error", str(e))

def redraw_preview():
    global _preview_photo, _preview_image
    canvas.delete("all")
    if _preview_image is None:
        return
    cw, ch = canvas.winfo_width(), canvas.winfo_height()
    img = _preview_image.copy()
    img.thumbnail((cw, ch), Image.LANCZOS)
    _preview_photo = ImageTk.PhotoImage(img)
    canvas.create_image(cw//2, ch//2, image=_preview_photo, anchor="center")

def choose_input():
    global input_image
    p = filedialog.askopenfilename(filetypes=[("PNG","*.png")])
    if p:
        input_image = p
        input_var.set(p)
        preview_image(p)
        update_capacity_label()

def choose_output():
    global output_image
    p = filedialog.asksaveasfilename(defaultextension=".png")
    if p:
        output_image = p
        output_var.set(p)

def choose_encoded():
    global encoded_image
    p = filedialog.askopenfilename(filetypes=[("PNG","*.png")])
    if p:
        encoded_image = p
        encoded_var.set(p)
        preview_image(p)

def update_capacity_label():
    if input_image:
        try:
            cap = capacity_for_image(input_image)
            cap_label_var.set(f"Image capacity: {cap} bytes")
        except Exception:
            cap_label_var.set("Image capacity: unknown")

def clear_all():
    global input_image, output_image, encoded_image
    input_image = output_image = encoded_image = ""
    input_var.set("")
    output_var.set("")
    encoded_var.set("")
    message_box.delete("1.0", "end")
    canvas.delete("all")
    set_status("Cleared")
    cap_label_var.set("Image capacity: -")

def prompt_load_or_generate_pub():
    """
    If public.pem missing, ask the user to load one or generate a new keypair.
    Returns path_to_public_key (string) or None if user cancels.
    If user generates, saves private.pem & public.pem in cwd and returns 'public.pem'.
    """
    if os.path.exists(public_key_path):
        return public_key_path

    resp = messagebox.askyesnocancel(
        "Public key not found",
        "No public.pem found. To encrypt for someone you must load their public key.\n\n"
        "Yes = Load a public key file now.\n"
        "No = Generate a NEW keypair (private.pem & public.pem) here and use it.\n"
        "Cancel = Abort encryption."
    )
    # note: askyesnocancel returns True (Yes), False (No), None (Cancel)
    if resp is None:
        return None
    if resp is True:
        # user chose Load
        p = filedialog.askopenfilename(title="Select public key (PEM)", filetypes=[("PEM files","*.pem")])
        if p:
            return p
        else:
            return None
    else:
        # user chose Generate (No)
        priv, pub = generate_rsa_keypair()
        save_private_key(priv, private_key_path)
        save_public_key(pub, public_key_path)
        messagebox.showinfo("Keys generated", f"Generated keypair:\n{os.path.abspath(private_key_path)}\n{os.path.abspath(public_key_path)}\n\nKeep your private key safe.")
        return public_key_path


# ---------- Actions ----------

def do_embed():
    global public_key_path
    if not input_image or not output_image:
        messagebox.showwarning("Missing", "Select input and output images.")
        return
    msg = message_box.get("1.0", "end").strip()
    if not msg:
        messagebox.showwarning("Missing", "Enter a message to hide.")
        return

    # Ensure we have a public key (either the project's public.pem or a loaded one,
    # or give the user the option to generate one right now)
    pub_path = None
    if os.path.exists(public_key_path):
        pub_path = public_key_path
    else:
        pub_path = prompt_load_or_generate_pub()
        if pub_path is None:
            set_status("Embed cancelled (no public key).")
            return
        # if user loaded a public key from other location, update runtime var so app uses it
        public_key_path = pub_path

    try:
        set_status("Encrypting message (AES) and wrapping key (RSA)...")
        pub = load_public_key(public_key_path)
        embed_message_rsa(input_image, output_image, msg, pub)
        msg_len = len(msg.encode('utf-8'))
        try:
            cap = capacity_for_image(input_image)
            set_status(f"Success — message embedded. message_bytes={msg_len}, image_capacity={cap} bytes")
        except Exception:
            set_status("Success — message embedded.")
        messagebox.showinfo("Done", f"Message encrypted & hidden to:\n{output_image}\n\nPublic key used: {os.path.abspath(public_key_path)}")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Failed")

def do_extract():
    if not encoded_image:
        messagebox.showwarning("Missing", "Select encoded image to extract.")
        return
    # Ensure private key exists
    if not os.path.exists(private_key_path):
        messagebox.showerror("Missing key", "private.pem not found. You need the private key to decrypt.")
        return

    try:
        set_status("Extracting payload and decrypting (RSA->AES)...")
        priv = load_private_key(private_key_path)
        plaintext = extract_message_rsa(encoded_image, priv)
        message_box.delete("1.0", "end")
        message_box.insert("1.0", plaintext)
        set_status("Success — message extracted")
        messagebox.showinfo("Done", "Message extracted and decrypted.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Failed")

# ---------- UI ----------
frame = ttk.Frame(ROOT, padding=10)
frame.pack(fill="both", expand=True)

# Vars
input_var = tk.StringVar()
output_var = tk.StringVar()
encoded_var = tk.StringVar()
status_var = tk.StringVar(value="Ready")
cap_label_var = tk.StringVar(value="Image capacity: -")

# Header
header = ttk.Frame(frame)
header.pack(fill="x", pady=(0,8))
ttk.Label(header, text=ASCII_ART, style="Ascii.TLabel", justify="left").pack(side="left", padx=6)
dev_frame = ttk.Frame(header)
dev_frame.pack(side="right")
ttk.Label(dev_frame, text="STEGACRYPT", style="Header.TLabel").pack(anchor="e")
ttk.Label(dev_frame, text="Developed by Chandan Agarwal", style="Dev.TLabel").pack(anchor="e")

# Left controls
left = ttk.Frame(frame)
left.pack(side="left", fill="y", padx=(0,12))

ttk.Label(left, text="Input Image (PNG)").pack(anchor="w")
ttk.Entry(left, textvariable=input_var, width=44).pack(anchor="w")
ttk.Button(left, text="Browse", command=choose_input).pack(anchor="w", pady=4)

ttk.Label(left, text="Save as (encoded) PNG").pack(anchor="w", pady=(8,0))
ttk.Entry(left, textvariable=output_var, width=44).pack(anchor="w")
ttk.Button(left, text="Choose", command=choose_output).pack(anchor="w", pady=4)

ttk.Label(left, text="Open encoded image (for extract)").pack(anchor="w", pady=(8,0))
ttk.Entry(left, textvariable=encoded_var, width=44).pack(anchor="w")
ttk.Button(left, text="Browse", command=choose_encoded).pack(anchor="w", pady=4)

ttk.Label(left, textvariable=cap_label_var, foreground="gray").pack(anchor="w", pady=(8,0))
ttk.Button(left, text="Clear", command=clear_all).pack(anchor="w", pady=(12,0))

# Right area (preview + message)
right = ttk.Frame(frame)
right.pack(side="left", fill="both", expand=True)

ttk.Label(right, text="Image Preview").pack(anchor="w")
canvas = tk.Canvas(right, bg="#111", bd=2, relief="sunken", height=360)
canvas.pack(fill="both", expand=True, pady=6)
canvas.bind("<Configure>", lambda e: redraw_preview())

ttk.Label(right, text="Message (input / output)").pack(anchor="w", pady=(8,0))
message_box = tk.Text(right, height=8, wrap="word")
message_box.pack(fill="x", pady=(4,8))

btns = ttk.Frame(right)
btns.pack(fill="x")
ttk.Button(btns, text="Encrypt & Hide (use public.pem)", command=do_embed).pack(side="left", padx=6, pady=6)
ttk.Button(btns, text="Extract & Decrypt (use private.pem)", command=do_extract).pack(side="left", padx=6, pady=6)

# Status bar
status_frame = ttk.Frame(ROOT)
status_frame.pack(fill="x", side="bottom")
ttk.Label(status_frame, textvariable=status_var).pack(anchor="w", padx=10, pady=6)

# On start: ensure keys exist and update capacity if an image already selected
generated = ensure_keys_exist()
if generated:
    messagebox.showinfo("Keys created", "RSA keypair created (private.pem & public.pem).\nKeep private.pem secret!")
set_status("Ready")

ROOT.mainloop()
