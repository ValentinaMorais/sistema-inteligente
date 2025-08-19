import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
import sqlite3
import csv
import bcrypt
import os

DB_NAME = "sistema.db"

# =========================
# BANCO DE DADOS
# =========================
def conn():
    return sqlite3.connect(DB_NAME)

def init_db():
    con = conn()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            senha BLOB NOT NULL,
            is_online INTEGER DEFAULT 0,
            last_login TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            prioridade TEXT NOT NULL,        -- Baixa, Média, Alta
            prazo TEXT NOT NULL,             -- dd/mm/yyyy HH:MM (SLA automático)
            status TEXT NOT NULL,            -- Aberto, Em Andamento, Fechado
            responsavel TEXT NOT NULL,
            criado_em TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()

init_db()

# =========================
# UTILS
# =========================
def bcrypt_hash(pwd: str) -> bytes:
    return bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt())

def bcrypt_check(pwd: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(pwd.encode("utf-8"), hashed)

def hoje_str_date():
    return datetime.now().strftime("%d/%m/%Y %H:%M")

def parse_prazo(prazo_str: str):
    """
    Tenta interpretar prazos nos formatos:
    - dd/mm/yyyy HH:MM
    - dd/mm/yyyy
    Retorna datetime ou None.
    """
    for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y"):
        try:
            return datetime.strptime(prazo_str, fmt)
        except:
            continue
    return None

def calc_sla_deadline(prioridade: str) -> str:
    """Retorna prazo no formato dd/mm/yyyy HH:MM com base na prioridade."""
    now = datetime.now()
    if prioridade == "Alta":
        delta = timedelta(hours=4)
    elif prioridade == "Média":
        delta = timedelta(hours=24)
    else:
        delta = timedelta(hours=72)
    prazo = now + delta
    return prazo.strftime("%d/%m/%Y %H:%M")

# =========================
# LOGIN WINDOW
# =========================
class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Login - Sistema Inteligente de Tickets")
        self.geometry("380x260")
        self.configure(bg="#f5f6fa")
        self.resizable(False, False)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TLabel", background="#f5f6fa", foreground="#2f3640", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.map("TButton", background=[("active", "#357ABD")], foreground=[("active", "white")])
        style.configure("TEntry", padding=4)

        title = tk.Label(self, text="Acesse sua conta", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 14, "bold"))
        title.pack(pady=(18, 8))

        frm = tk.Frame(self, bg="#f5f6fa")
        frm.pack(pady=4)

        tk.Label(frm, text="Usuário:", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.e_user = ttk.Entry(frm, width=28)
        self.e_user.grid(row=0, column=1, padx=6, pady=6)

        tk.Label(frm, text="Senha:", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.e_pwd = ttk.Entry(frm, width=28, show="*")
        self.e_pwd.grid(row=1, column=1, padx=6, pady=6)

        btns = tk.Frame(self, bg="#f5f6fa")
        btns.pack(pady=10)

        ttk.Button(btns, text="Entrar", command=self.login).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Registrar", command=self.registrar).grid(row=0, column=1, padx=6)

        self.bind("<Return>", lambda e: self.login())

    def registrar(self):
        u = self.e_user.get().strip()
        p = self.e_pwd.get().strip()
        if not u or not p:
            messagebox.showerror("Erro", "Preencha usuário e senha.")
            return
        con = conn()
        cur = con.cursor()
        try:
            cur.execute("INSERT INTO usuarios (usuario, senha) VALUES (?,?)", (u, bcrypt_hash(p)))
            con.commit()
            messagebox.showinfo("Sucesso", "Usuário registrado!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Erro", "Usuário já existe.")
        finally:
            con.close()

    def login(self):
        u = self.e_user.get().strip()
        p = self.e_pwd.get().strip()
        con = conn()
        cur = con.cursor()
        cur.execute("SELECT senha FROM usuarios WHERE usuario=?", (u,))
        row = cur.fetchone()
        if row and bcrypt_check(p, row[0]):
            cur.execute("UPDATE usuarios SET is_online=1, last_login=? WHERE usuario=?", (datetime.now().isoformat(timespec="seconds"), u))
            con.commit()
            con.close()
            self.destroy()
            MainApp(usuario=u).mainloop()
        else:
            con.close()
            messagebox.showerror("Erro", "Usuário ou senha inválidos.")

# =========================
# MAIN APP
# =========================
class MainApp(tk.Tk):
    def __init__(self, usuario: str):
        super().__init__()
        self.usuario = usuario
        self.title("Sistema Inteligente de Gestão de Tickets")
        self.geometry("1100x680")
        self.configure(bg="#f5f6fa")

        self.protocol("WM_DELETE_WINDOW", self.sair)

        # estilos
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TLabel", background="#f5f6fa", foreground="#2f3640", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.map("TButton", background=[("active", "#357ABD")], foreground=[("active", "white")])
        style.configure("TEntry", padding=4)
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=26, fieldbackground="#ffffff", background="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#4a90e2")], foreground=[("selected", "white")])

        # ---------- Banner ----------
        self.banner = tk.Label(self, text="", anchor="w", padx=12, pady=6, font=("Segoe UI", 10, "bold"))
        self.banner.pack(fill=tk.X, padx=10, pady=(10, 6))
        self._set_banner(f"Bem-vinda(o), {self.usuario}! Use os filtros para localizar tickets rapidamente.", bg="#e8f1ff", fg="#184a90")

        # ---------- Topbar (filtros + ações) ----------
        topbar = tk.Frame(self, bg="#f5f6fa")
        topbar.pack(fill=tk.X, padx=10)

        tk.Label(topbar, text="Buscar:", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, padx=6, pady=4)
        self.e_busca = ttk.Entry(topbar, width=28)
        self.e_busca.grid(row=0, column=1, padx=6, pady=4)
        self.e_busca.bind("<KeyRelease>", lambda e: self.carregar_tickets())

        tk.Label(topbar, text="Prioridade:", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold")).grid(row=0, column=2, padx=6)
        self.f_prio = ttk.Combobox(topbar, values=["", "Baixa", "Média", "Alta"], width=12, state="readonly")
        self.f_prio.grid(row=0, column=3, padx=6)
        self.f_prio.bind("<<ComboboxSelected>>", lambda e: self.carregar_tickets())

        tk.Label(topbar, text="Status:", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold")).grid(row=0, column=4, padx=6)
        self.f_status = ttk.Combobox(topbar, values=["", "Aberto", "Em Andamento", "Fechado"], width=15, state="readonly")
        self.f_status.grid(row=0, column=5, padx=6)
        self.f_status.bind("<<ComboboxSelected>>", lambda e: self.carregar_tickets())

        ttk.Button(topbar, text="Exportar CSV", command=self.exportar_csv).grid(row=0, column=6, padx=10)
        ttk.Button(topbar, text="Sair", command=self.sair).grid(row=0, column=7, padx=6)

        # ---------- Formulário de criação (prazo automático por SLA) ----------
        form = tk.LabelFrame(self, text="Novo Ticket", bg="#f5f6fa", fg="#2f3640", padx=10, pady=8, font=("Segoe UI", 10, "bold"))
        form.pack(fill=tk.X, padx=10, pady=(6, 6))

        tk.Label(form, text="Título:", bg="#f5f6fa", fg="#2f3640").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.e_titulo = ttk.Entry(form, width=40)
        self.e_titulo.grid(row=0, column=1, padx=6, pady=4, sticky="w")

        tk.Label(form, text="Descrição:", bg="#f5f6fa", fg="#2f3640").grid(row=1, column=0, sticky="ne", padx=6, pady=4)
        self.txt_desc = tk.Text(form, width=50, height=4, relief="solid", bd=1)
        self.txt_desc.grid(row=1, column=1, padx=6, pady=4, sticky="w")

        tk.Label(form, text="Prioridade:", bg="#f5f6fa", fg="#2f3640").grid(row=0, column=2, sticky="e", padx=6, pady=4)
        self.cb_prio = ttk.Combobox(form, values=["Baixa", "Média", "Alta"], width=12, state="readonly")
        self.cb_prio.grid(row=0, column=3, padx=6, pady=4)

        # Informação do SLA calculado
        self.lbl_sla_info = tk.Label(form, text="Prazo será calculado automaticamente pelo SLA.", bg="#f5f6fa", fg="#6b7280", font=("Segoe UI", 9, "italic"))
        self.lbl_sla_info.grid(row=1, column=2, columnspan=2, padx=6, pady=4, sticky="w")

        ttk.Button(form, text="Criar Ticket", command=self.criar_ticket).grid(row=0, column=4, rowspan=2, padx=10, pady=4, sticky="ns")

        # ---------- Tabela ----------
        frame_tbl = tk.Frame(self, bg="#f5f6fa")
        frame_tbl.pack(fill=tk.BOTH, expand=True, padx=10)

        cols = ("ID", "Título", "Descrição", "Prioridade", "Prazo", "Status")
        self.tree = ttk.Treeview(frame_tbl, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("ID", width=60, anchor="center")
        self.tree.column("Título", width=220)
        self.tree.column("Descrição", width=320)
        self.tree.column("Prioridade", width=100, anchor="center")
        self.tree.column("Prazo", width=170, anchor="center")  # agora mostra data e hora
        self.tree.column("Status", width=130, anchor="center")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        sb = ttk.Scrollbar(frame_tbl, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Tags de cor
        self.tree.tag_configure("prio_alta", background="#ffe5e5")
        self.tree.tag_configure("prio_media", background="#fff7e0")
        self.tree.tag_configure("prio_baixa", background="#eaf7ea")
        self.tree.tag_configure("vencido", background="#ffd6d6")
        self.tree.tag_configure("hoje", background="#fff1cc")

        # ---------- Ações ----------
        actions = tk.Frame(self, bg="#f5f6fa")
        actions.pack(fill=tk.X, padx=10, pady=(6, 10))

        tk.Label(actions, text="Status:", bg="#f5f6fa", fg="#2f3640").pack(side=tk.LEFT, padx=(0,6))
        self.cb_status = ttk.Combobox(actions, values=["Aberto", "Em Andamento", "Fechado"], state="readonly", width=18)
        self.cb_status.pack(side=tk.LEFT, padx=(0,10))

        ttk.Button(actions, text="Atualizar Status", command=self.atualizar_status).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Editar Ticket", command=self.editar_ticket).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Excluir Ticket", command=self.excluir_ticket).pack(side=tk.LEFT, padx=4)

        # ---------- Painel lateral ----------
        sidebar = tk.LabelFrame(self, text="Painel", bg="#f5f6fa", fg="#2f3640", padx=10, pady=8, font=("Segoe UI", 10, "bold"))
        sidebar.pack(fill=tk.X, padx=10, pady=(0, 8))

        self.lbl_kpi_abertos = tk.Label(sidebar, text="Abertos: 0", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold"))
        self.lbl_kpi_and = tk.Label(sidebar, text="Em Andamento: 0", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold"))
        self.lbl_kpi_fech = tk.Label(sidebar, text="Fechados: 0", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold"))
        self.lbl_kpi_prox = tk.Label(sidebar, text="Prazos próximos (<=1 dia): 0", bg="#f5f6fa", fg="#8a4b00", font=("Segoe UI", 10, "bold"))
        self.lbl_kpi_venc = tk.Label(sidebar, text="Vencidos: 0", bg="#f5f6fa", fg="#8a0000", font=("Segoe UI", 10, "bold"))

        self.lbl_kpi_abertos.grid(row=0, column=0, padx=8, pady=4, sticky="w")
        self.lbl_kpi_and.grid(row=0, column=1, padx=8, pady=4, sticky="w")
        self.lbl_kpi_fech.grid(row=0, column=2, padx=8, pady=4, sticky="w")
        self.lbl_kpi_prox.grid(row=1, column=0, padx=8, pady=4, sticky="w")
        self.lbl_kpi_venc.grid(row=1, column=1, padx=8, pady=4, sticky="w")

        box_online = tk.Frame(sidebar, bg="#f5f6fa")
        box_online.grid(row=0, column=3, rowspan=2, padx=(30,0), sticky="e")
        tk.Label(box_online, text="Usuários online:", bg="#f5f6fa", fg="#2f3640", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.list_online = tk.Listbox(box_online, width=22, height=4)
        self.list_online.pack()

        self.carregar_tickets()
        self.atualizar_online()
        self.after(1000 * 60, self._refresh_online_periodico)

    # ---------- Banner ----------
    def _set_banner(self, texto, bg="#e8f1ff", fg="#184a90"):
        self.banner.configure(text=texto, bg=bg, fg=fg)

    # ---------- CRUD ----------
    def criar_ticket(self):
        titulo = self.e_titulo.get().strip()
        desc = self.txt_desc.get("1.0", tk.END).strip()
        prio = self.cb_prio.get().strip()

        if not (titulo and desc and prio):
            messagebox.showerror("Erro", "Preencha título, descrição e prioridade.")
            return

        # SLA automático
        prazo_calc = calc_sla_deadline(prio)

        con = conn()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO tickets (titulo, descricao, prioridade, prazo, status, responsavel, criado_em)
            VALUES (?,?,?,?,?,?,?)
        """, (titulo, desc, prio, prazo_calc, "Aberto", self.usuario, hoje_str_date()))
        con.commit()
        con.close()

        self.e_titulo.delete(0, tk.END)
        self.txt_desc.delete("1.0", tk.END)
        self.cb_prio.set("")

        self._set_banner(f"Ticket criado com sucesso. Prazo (SLA): {prazo_calc}", bg="#e6ffed", fg="#075e2b")
        self.carregar_tickets()

    def editar_ticket(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Atenção", "Selecione um ticket.")
            return
        ticket_id = self.tree.item(sel[0])["values"][0]

        con = conn()
        cur = con.cursor()
        cur.execute("SELECT titulo, descricao, prioridade, prazo, status FROM tickets WHERE id=?", (ticket_id,))
        row = cur.fetchone()
        con.close()
        if not row:
            messagebox.showerror("Erro", "Ticket não encontrado.")
            return

        top = tk.Toplevel(self)
        top.title(f"Editar Ticket #{ticket_id}")
        top.geometry("600x460")
        top.configure(bg="#f5f6fa")
        top.grab_set()

        tk.Label(top, text="Título:", bg="#f5f6fa").grid(row=0, column=0, sticky="e", padx=8, pady=6)
        e_titulo = ttk.Entry(top, width=50)
        e_titulo.grid(row=0, column=1, padx=8, pady=6, sticky="w")

        tk.Label(top, text="Descrição:", bg="#f5f6fa").grid(row=1, column=0, sticky="ne", padx=8, pady=6)
        t_desc = tk.Text(top, width=50, height=6, relief="solid", bd=1)
        t_desc.grid(row=1, column=1, padx=8, pady=6, sticky="w")

        tk.Label(top, text="Prioridade:", bg="#f5f6fa").grid(row=2, column=0, sticky="e", padx=8, pady=6)
        cb_prio = ttk.Combobox(top, values=["Baixa", "Média", "Alta"], width=14, state="readonly")
        cb_prio.grid(row=2, column=1, padx=8, pady=6, sticky="w")

        tk.Label(top, text="Prazo (SLA):", bg="#f5f6fa").grid(row=3, column=0, sticky="e", padx=8, pady=6)
        e_prazo = ttk.Entry(top, width=20, state="readonly")
        e_prazo.grid(row=3, column=1, padx=8, pady=6, sticky="w")

        tk.Label(top, text="Status:", bg="#f5f6fa").grid(row=4, column=0, sticky="e", padx=8, pady=6)
        cb_status = ttk.Combobox(top, values=["Aberto", "Em Andamento", "Fechado"], width=18, state="readonly")
        cb_status.grid(row=4, column=1, padx=8, pady=6, sticky="w")

        # preencher
        e_titulo.insert(0, row[0])
        t_desc.insert("1.0", row[1])
        cb_prio.set(row[2])
        e_prazo.configure(state="normal")
        e_prazo.delete(0, tk.END)
        e_prazo.insert(0, row[3])
        e_prazo.configure(state="readonly")
        cb_status.set(row[4])

        def on_prio_change(_):
            # recalcula SLA ao trocar prioridade
            novo_prazo = calc_sla_deadline(cb_prio.get().strip())
            e_prazo.configure(state="normal")
            e_prazo.delete(0, tk.END)
            e_prazo.insert(0, novo_prazo)
            e_prazo.configure(state="readonly")

        cb_prio.bind("<<ComboboxSelected>>", on_prio_change)

        def salvar_edicao():
            novo_titulo = e_titulo.get().strip()
            nova_desc = t_desc.get("1.0", tk.END).strip()
            nova_prio = cb_prio.get().strip()
            novo_prazo = e_prazo.get().strip()  # já vem do SLA
            novo_status = cb_status.get().strip()

            if not (novo_titulo and nova_desc and nova_prio and novo_prazo and novo_status):
                messagebox.showerror("Erro", "Preencha todos os campos.")
                return

            con2 = conn()
            cur2 = con2.cursor()
            cur2.execute("""
                UPDATE tickets SET titulo=?, descricao=?, prioridade=?, prazo=?, status=?
                WHERE id=?
            """, (novo_titulo, nova_desc, nova_prio, novo_prazo, novo_status, ticket_id))
            con2.commit()
            con2.close()

            self._set_banner(f"Ticket #{ticket_id} atualizado. Novo prazo (SLA): {novo_prazo}", bg="#e6ffed", fg="#075e2b")
            self.carregar_tickets()
            top.destroy()

        btns = tk.Frame(top, bg="#f5f6fa")
        btns.grid(row=5, column=0, columnspan=2, pady=12)
        ttk.Button(btns, text="Salvar alterações", command=salvar_edicao).pack(side=tk.LEFT, padx=8)
        ttk.Button(btns, text="Cancelar", command=top.destroy).pack(side=tk.LEFT, padx=8)

    def excluir_ticket(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Atenção", "Selecione um ticket.")
            return
        ticket_id = self.tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirmação", f"Deseja excluir o ticket #{ticket_id}?"):
            con = conn()
            cur = con.cursor()
            cur.execute("DELETE FROM tickets WHERE id=?", (ticket_id,))
            con.commit()
            con.close()
            self._set_banner(f"Ticket #{ticket_id} excluído.", bg="#fff2e8", fg="#7a2e00")
            self.carregar_tickets()

    def atualizar_status(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Atenção", "Selecione um ticket.")
            return
        ticket_id = self.tree.item(sel[0])["values"][0]
        novo = self.cb_status.get().strip()
        if not novo:
            messagebox.showwarning("Atenção", "Selecione um status.")
            return
        con = conn()
        cur = con.cursor()
        cur.execute("UPDATE tickets SET status=? WHERE id=?", (novo, ticket_id))
        con.commit()
        con.close()
        self._set_banner(f"Status do ticket #{ticket_id} atualizado para '{novo}'.", bg="#e6ffed", fg="#075e2b")
        self.carregar_tickets()

    # ---------- LISTAGEM / CORES / KPIs ----------
    def carregar_tickets(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        q = self.e_busca.get().strip().lower()
        f_prio = self.f_prio.get().strip()
        f_status = self.f_status.get().strip()

        con = conn()
        cur = con.cursor()
        cur.execute("""
            SELECT id, titulo, descricao, prioridade, prazo, status
            FROM tickets
            WHERE responsavel=?
        """, (self.usuario,))
        rows = cur.fetchall()
        con.close()

        abertos = em_and = fechados = prox = venc = 0
        agora = datetime.now()

        for r in rows:
            id_, titulo, desc, prio, prazo, status = r
            if q and (q not in titulo.lower() and q not in desc.lower()):
                continue
            if f_prio and prio != f_prio:
                continue
            if f_status and status != f_status:
                continue

            tags = []
            if prio == "Alta":
                tags.append("prio_alta")
            elif prio == "Média":
                tags.append("prio_media")
            else:
                tags.append("prio_baixa")

            prazo_dt = parse_prazo(prazo)
            if prazo_dt:
                if prazo_dt < agora:
                    tags.append("vencido")
                    venc += 1
                elif prazo_dt.date() == agora.date() or prazo_dt <= agora + timedelta(days=1):
                    tags.append("hoje")
                    prox += 1

            if status == "Aberto":
                abertos += 1
            elif status == "Em Andamento":
                em_and += 1
            else:
                fechados += 1

            self.tree.insert("", "end", values=(id_, titulo, desc, prio, prazo, status), tags=tuple(tags))

        self.lbl_kpi_abertos.config(text=f"Abertos: {abertos}")
        self.lbl_kpi_and.config(text=f"Em Andamento: {em_and}")
        self.lbl_kpi_fech.config(text=f"Fechados: {fechados}")
        self.lbl_kpi_prox.config(text=f"Prazos próximos (<=1 dia): {prox}")
        self.lbl_kpi_venc.config(text=f"Vencidos: {venc}")

        if venc > 0:
            self._set_banner(f"Atenção: {venc} ticket(s) com prazo vencido.", bg="#ffecec", fg="#7a0000")
        elif prox > 0:
            self._set_banner(f"Você tem {prox} ticket(s) com prazo até hoje/amanhã.", bg="#fff8e6", fg="#7a4d00")
        else:
            self._set_banner("Lista atualizada.", bg="#e8f1ff", fg="#184a90")

    # ---------- CSV ----------
    def exportar_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"tickets_{self.usuario}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        )
        if not path:
            return

        con = conn()
        cur = con.cursor()
        cur.execute("""
            SELECT id, titulo, descricao, prioridade, prazo, status, responsavel, criado_em
            FROM tickets WHERE responsavel=?
        """, (self.usuario,))
        rows = cur.fetchall()
        con.close()

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["ID", "Título", "Descrição", "Prioridade", "Prazo (SLA)", "Status", "Responsável", "Criado em"])
                for r in rows:
                    w.writerow(r)
            messagebox.showinfo("Sucesso", "CSV exportado com sucesso.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar CSV:\n{e}")

    # ---------- ONLINE ----------
    def atualizar_online(self):
        self.list_online.delete(0, tk.END)
        con = conn()
        cur = con.cursor()
        cur.execute("SELECT usuario FROM usuarios WHERE is_online=1")
        for (u,) in cur.fetchall():
            self.list_online.insert(tk.END, u)
        con.close()

    def _refresh_online_periodico(self):
        self.atualizar_online()
        self.after(1000 * 60, self._refresh_online_periodico)

    # ---------- SAIR ----------
    def sair(self):
        try:
            con = conn()
            cur = con.cursor()
            cur.execute("UPDATE usuarios SET is_online=0 WHERE usuario=?", (self.usuario,))
            con.commit()
            con.close()
        except:
            pass
        self.destroy()

# =========================
# RUN
# =========================
if __name__ == "__main__":
    # Para resetar do zero (opcional): 
    # if os.path.exists(DB_NAME): os.remove(DB_NAME); init_db()
    LoginWindow().mainloop()
