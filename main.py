import tkinter as tk
from tkinter import ttk, messagebox
from tkcalendar import DateEntry
import sqlite3
import bcrypt
import datetime

# --------------------------
# BANCO DE DADOS
# --------------------------
conn = sqlite3.connect("sistema_inteligente.db")
cursor = conn.cursor()

# Tabela de usuários
cursor.execute("""
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL
)
""")

# Tabela de tickets
cursor.execute("""
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL,
    descricao TEXT,
    prioridade TEXT,
    prazo DATE,
    status TEXT DEFAULT 'Aberto',
    responsavel TEXT
)
""")
conn.commit()

# --------------------------
# FUNÇÕES
# --------------------------

def registrar_usuario(usuario, senha):
    senha_hash = bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", (usuario, senha_hash))
        conn.commit()
        messagebox.showinfo("Sucesso", "Usuário registrado com sucesso!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Erro", "Usuário já existe!")

def login():
    usuario = entry_usuario.get()
    senha = entry_senha.get()
    cursor.execute("SELECT senha FROM usuarios WHERE usuario=?", (usuario,))
    result = cursor.fetchone()

    if result and bcrypt.checkpw(senha.encode("utf-8"), result[0]):
        messagebox.showinfo("Sucesso", f"Bem-vindo, {usuario}!")
        abrir_dashboard(usuario)
    else:
        messagebox.showerror("Erro", "Usuário ou senha inválidos.")

def abrir_dashboard(usuario):
    login_window.destroy()

    dashboard = tk.Tk()
    dashboard.title("Sistema Inteligente de Tickets")
    dashboard.geometry("800x600")

    # --------------------------
    # Banner de notificações
    # --------------------------
    frame_banner = tk.Frame(dashboard)
    frame_banner.pack(fill="x", pady=5)

    hoje = datetime.date.today()
    cursor.execute("""
        SELECT titulo, prazo FROM tickets 
        WHERE responsavel=? AND status='Aberto'
    """, (usuario,))
    tickets_usuario = cursor.fetchall()

    alertas = []
    for titulo, prazo in tickets_usuario:
        if prazo:
            prazo_data = datetime.datetime.strptime(prazo, "%Y-%m-%d").date()
            if prazo < str(hoje):
                alertas.append(("vermelho", f"⚠ Ticket '{titulo}' está ATRASADO! Prazo era {prazo_data}"))
            elif prazo_data == hoje or prazo_data == hoje + datetime.timedelta(days=1):
                alertas.append(("amarelo", f"⚠ Ticket '{titulo}' vence em breve ({prazo_data})"))

    if alertas:
        for cor, msg in alertas:
            banner = tk.Label(frame_banner, text=msg, fg="white", bg=cor, font=("Arial", 10, "bold"))
            banner.pack(fill="x", padx=5, pady=2)

    # --------------------------
    # Formulário de criação
    # --------------------------
    frame_form = tk.Frame(dashboard)
    frame_form.pack(pady=10)

    tk.Label(frame_form, text="Título:").grid(row=0, column=0)
    entry_titulo = tk.Entry(frame_form)
    entry_titulo.grid(row=0, column=1)

    tk.Label(frame_form, text="Descrição:").grid(row=1, column=0)
    entry_desc = tk.Entry(frame_form)
    entry_desc.grid(row=1, column=1)

    tk.Label(frame_form, text="Prioridade:").grid(row=2, column=0)
    combo_prio = ttk.Combobox(frame_form, values=["Baixa", "Média", "Alta"])
    combo_prio.grid(row=2, column=1)

    tk.Label(frame_form, text="Prazo:").grid(row=3, column=0)
    entry_prazo = DateEntry(frame_form, date_pattern="yyyy-mm-dd")
    entry_prazo.grid(row=3, column=1)

    def salvar():
        titulo = entry_titulo.get()
        desc = entry_desc.get()
        prio = combo_prio.get()
        prazo = entry_prazo.get_date().strftime("%Y-%m-%d")

        if not titulo or not prio or not prazo:
            messagebox.showerror("Erro", "Preencha todos os campos obrigatórios!")
            return

        cursor.execute("""
            INSERT INTO tickets (titulo, descricao, prioridade, prazo, status, responsavel)
            VALUES (?, ?, ?, ?, 'Aberto', ?)
        """, (titulo, desc, prio, prazo, usuario))
        conn.commit()
        messagebox.showinfo("Sucesso", "Ticket criado com sucesso!")
        atualizar_lista()

    btn_salvar = tk.Button(frame_form, text="Criar Ticket", command=salvar)
    btn_salvar.grid(row=4, column=1, pady=5)

    # --------------------------
    # Lista de tickets
    # --------------------------
    frame_lista = tk.Frame(dashboard)
    frame_lista.pack(pady=10, fill="both", expand=True)

    colunas = ("ID", "Título", "Descrição", "Prioridade", "Prazo", "Status")
    tree = ttk.Treeview(frame_lista, columns=colunas, show="headings")
    for col in colunas:
        tree.heading(col, text=col)
        tree.column(col, width=100)
    tree.pack(fill="both", expand=True)

    def atualizar_lista():
        for row in tree.get_children():
            tree.delete(row)
        cursor.execute("SELECT id, titulo, descricao, prioridade, prazo, status FROM tickets WHERE responsavel=?", (usuario,))
        for row in cursor.fetchall():
            tree.insert("", "end", values=row)

    atualizar_lista()
    dashboard.mainloop()

# --------------------------
# LOGIN WINDOW
# --------------------------
login_window = tk.Tk()
login_window.title("Login - Sistema Inteligente")
login_window.geometry("300x200")

tk.Label(login_window, text="Usuário:").pack()
entry_usuario = tk.Entry(login_window)
entry_usuario.pack()

tk.Label(login_window, text="Senha:").pack()
entry_senha = tk.Entry(login_window, show="*")
entry_senha.pack()

btn_login = tk.Button(login_window, text="Login", command=login)
btn_login.pack(pady=5)

btn_registrar = tk.Button(login_window, text="Registrar", command=lambda: registrar_usuario(entry_usuario.get(), entry_senha.get()))
btn_registrar.pack(pady=5)

login_window.mainloop()
