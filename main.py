import sqlite3
import threading
import time
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import bcrypt

DB_NAME = "tickets.db"

# ---------------------------- Banco ----------------------------
def get_conn():
    # check_same_thread=False para permitir uso no thread de verificação
    return sqlite3.connect(DB_NAME, check_same_thread=False)

def _senha_to_bytes(senha_val):
    """Normaliza o campo senha vindo do SQLite para bytes."""
    # Pode vir como bytes, memoryview ou str dependendo do schema antigo
    if isinstance(senha_val, (bytes, bytearray)):
        return bytes(senha_val)
    if isinstance(senha_val, memoryview):
        return bytes(senha_val.tobytes())
    if isinstance(senha_val, str):
        # Se for hash bcrypt em string ("$2b$..."), encode resolve
        if senha_val.startswith("$2"):
            return senha_val.encode("utf-8")
        # Caso seja texto puro (ex: '123'), retornamos None para tratar fora
        return None
    return None

def migrar_usuarios_para_blob(cur, conn):
    """Se a coluna usuarios.senha não for BLOB, migra e corrige os dados."""
    cur.execute("PRAGMA table_info(usuarios)")
    cols = cur.fetchall()  # cid, name, type, notnull, dflt_value, pk
    senha_type = None
    for cid, name, coltype, *_ in cols:
        if name == "senha":
            senha_type = (coltype or "").upper()
            break

    if senha_type == "BLOB":
        return  # já está ok

    # Se não existe/é outro tipo, migrar
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
    if not cur.fetchone():
        # Tabela nem existe; será criada adiante em preparar_banco()
        return

    # Renomeia antiga
    cur.execute("ALTER TABLE usuarios RENAME TO usuarios_old")

    # Cria nova com BLOB
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            senha BLOB NOT NULL
        )
    """)

    # Copia e converte
    try:
        cur.execute("SELECT id, usuario, senha FROM usuarios_old")
        for uid, user, senha_antiga in cur.fetchall():
            hashed = _senha_to_bytes(senha_antiga)
            if hashed is None:
                # Provavelmente senha em texto puro: rehash
                if isinstance(senha_antiga, str) and senha_antiga:
                    hashed = bcrypt.hashpw(senha_antiga.encode("utf-8"), bcrypt.gensalt())
                else:
                    # Sem como recuperar => força redefinição para '123' com aviso no log
                    hashed = bcrypt.hashpw(b"123", bcrypt.gensalt())
            cur.execute("INSERT OR REPLACE INTO usuarios (id, usuario, senha) VALUES (?, ?, ?)",
                        (uid, user, hashed))
        conn.commit()
    finally:
        cur.execute("DROP TABLE IF EXISTS usuarios_old")
        conn.commit()

def preparar_banco():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            senha BLOB NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            titulo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            prioridade TEXT NOT NULL,
            status TEXT NOT NULL,
            prazo TEXT,
            criado_em TEXT NOT NULL,
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        )
    """)
    conn.commit()

    # Migra se necessário (corrige TEXT -> BLOB e senhas antigas)
    migrar_usuarios_para_blob(cur, conn)

    # Usuário padrão se não existir
    cur.execute("SELECT id FROM usuarios WHERE usuario=?", ("admin",))
    if not cur.fetchone():
        senha_hash = bcrypt.hashpw(b"123", bcrypt.gensalt())
        cur.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", ("admin", senha_hash))
        conn.commit()

    conn.close()

# ---------------------------- Estilo ----------------------------
def configurar_estilo():
    style = ttk.Style()
    style.theme_use("clam")

    style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=8)
    style.map("TButton", background=[("active", "#2e7d32")])

    style.configure("Treeview.Heading",
                    font=("Segoe UI", 11, "bold"),
                    background="#4CAF50",
                    foreground="white")
    style.configure("Treeview",
                    font=("Segoe UI", 10),
                    rowheight=28)

    style.configure("TLabel", font=("Segoe UI", 10))
    style.configure("TCombobox", selectbackground="#e8f5e9", fieldbackground="white")

# ---------------------------- Utils ----------------------------
def parse_data_flex(texto):
    """Aceita 'DD/MM/YYYY' ou 'YYYY-MM-DD'. Retorna datetime ou None."""
    if not texto:
        return None
    for fmt in ("%d/%m/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(texto.strip(), fmt)
        except ValueError:
            pass
    return None

def formata_data(dt):
    return dt.strftime("%d/%m/%Y") if dt else ""

# ---------------------------- App ----------------------------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema Inteligente de Tickets")
        self.root.geometry("980x620")
        self.root.minsize(980, 620)
        configurar_estilo()

        self.conn = get_conn()
        self.cur = self.conn.cursor()

        self.usuario = None      # (id, usuario)
        self.alertados = set()   # ids de tickets já alertados

        self._montar_tela_login()

    # ---------- Login ----------
    def _montar_tela_login(self):
        self._limpar_root()
        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True)

        ttk.Label(frame, text="Login - Sistema Inteligente de Tickets",
                  font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 20))

        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="e", padx=10, pady=8)
        self.ent_user = ttk.Entry(frame, width=32)
        self.ent_user.grid(row=1, column=1, pady=8)
        self.ent_user.focus()

        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="e", padx=10, pady=8)
        self.ent_pwd = ttk.Entry(frame, show="*", width=32)
        self.ent_pwd.grid(row=2, column=1, pady=8)

        btns = ttk.Frame(frame)
        btns.grid(row=3, column=0, columnspan=2, pady=15)

        ttk.Button(btns, text="Entrar", command=self._login).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Registrar", command=self._registrar).grid(row=0, column=1, padx=6)

        self.ent_user.bind("<Return>", lambda e: self._login())
        self.ent_pwd.bind("<Return>", lambda e: self._login())

    def _login(self):
        user = self.ent_user.get().strip()
        pwd = self.ent_pwd.get().strip()
        if not user or not pwd:
            messagebox.showwarning("Aviso", "Preencha usuário e senha.")
            return

        self.cur.execute("SELECT id, senha FROM usuarios WHERE usuario=?", (user,))
        row = self.cur.fetchone()
        if not row:
            messagebox.showerror("Erro", "Usuário não encontrado.")
            return

        uid, senha_val = row
        hashed = _senha_to_bytes(senha_val)

        # Se veio None aqui, é porque achou texto puro na tabela já migrada (caso raríssimo)
        if hashed is None:
            # Converte agora (rehash) e salva
            try:
                new_hash = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt())
                self.cur.execute("UPDATE usuarios SET senha=? WHERE id=?", (new_hash, uid))
                self.conn.commit()
                hashed = new_hash
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao validar senha: {e}")
                return

        try:
            if bcrypt.checkpw(pwd.encode("utf-8"), hashed):
                self.usuario = (uid, user)
                self._montar_tela_principal()
                self._iniciar_verificador_prazos()
            else:
                messagebox.showerror("Erro", "Senha incorreta.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao validar senha: {e}")

    def _registrar(self):
        user = self.ent_user.get().strip()
        pwd = self.ent_pwd.get().strip()
        if not user or not pwd:
            messagebox.showwarning("Aviso", "Usuário e senha não podem ser vazios.")
            return
        try:
            self.cur.execute("SELECT 1 FROM usuarios WHERE usuario=?", (user,))
            if self.cur.fetchone():
                messagebox.showerror("Erro", "Usuário já existe.")
                return
            senha_hash = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt())
            self.cur.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", (user, senha_hash))
            self.conn.commit()
            messagebox.showinfo("Sucesso", "Usuário registrado. Agora faça login.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao registrar: {e}")

    # ---------- Principal ----------
    def _montar_tela_principal(self):
        self._limpar_root()

        top = ttk.Frame(self.root, padding=(12, 10))
        top.pack(fill="x")

        ttk.Label(top, text=f"Logado como: {self.usuario[1]}",
                  font=("Segoe UI", 11, "bold")).pack(side="left")

        toolbar = ttk.Frame(top)
        toolbar.pack(side="right")

        ttk.Button(toolbar, text="Novo Ticket", command=self._abrir_modal_ticket).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Atualizar", command=self._carregar_tickets).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Exportar CSV", command=self._exportar_csv).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Sair", command=self._logout).pack(side="left", padx=5)

        cols = ("ID", "Título", "Descrição", "Prioridade", "Status", "Prazo", "Criado em")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings")
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        larguras = [60, 220, 340, 100, 120, 110, 130]
        for i, col in enumerate(cols):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=larguras[i], anchor="center")

        # Cores de prioridade
        self.tree.tag_configure("Alta", background="#ff6b6b")
        self.tree.tag_configure("Média", background="#ffd93b")
        self.tree.tag_configure("Baixa", background="#6bcb77")

        self._carregar_tickets()

    def _carregar_tickets(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.cur.execute("""
           SELECT id, titulo, descricao, prioridade, status, prazo, criado_em
           FROM tickets
           WHERE usuario_id=?
           ORDER BY datetime(substr(criado_em,7,4)||'-'||substr(criado_em,4,2)||'-'||substr(criado_em,1,2) || ' ' || substr(criado_em,12,5)) DESC
        """, (self.usuario[0],))
        for row in self.cur.fetchall():
            prioridade = row[3]
            self.tree.insert("", "end", values=row, tags=(prioridade,))

    def _abrir_modal_ticket(self):
        win = tk.Toplevel(self.root)
        win.title("Novo Ticket")
        win.transient(self.root)
        win.grab_set()
        win.geometry("580x420")

        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Título:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="e", pady=6, padx=6)
        ent_titulo = ttk.Entry(frm, width=46)
        ent_titulo.grid(row=0, column=1, sticky="w", pady=6)

        ttk.Label(frm, text="Descrição:", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="ne", pady=6, padx=6)
        txt_desc = tk.Text(frm, width=44, height=8, font=("Segoe UI", 10))
        txt_desc.grid(row=1, column=1, sticky="w", pady=6)

        ttk.Label(frm, text="Prioridade:", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="e", pady=6, padx=6)
        cmb_prio = ttk.Combobox(frm, values=["Alta", "Média", "Baixa"], state="readonly", width=43)
        cmb_prio.grid(row=2, column=1, sticky="w", pady=6)
        cmb_prio.current(1)

        ttk.Label(frm, text="Status:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="e", pady=6, padx=6)
        cmb_status = ttk.Combobox(frm, values=["Aberto", "Em andamento", "Fechado"], state="readonly", width=43)
        cmb_status.grid(row=3, column=1, sticky="w", pady=6)
        cmb_status.current(0)

        ttk.Label(frm, text="Prazo (DD/MM/YYYY):", font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="e", pady=6, padx=6)
        ent_prazo = ttk.Entry(frm, width=20)
        ent_prazo.grid(row=4, column=1, sticky="w", pady=6)

        barra = ttk.Frame(frm)
        barra.grid(row=5, column=0, columnspan=2, pady=12)

        def salvar():
            titulo = ent_titulo.get().strip()
            desc = txt_desc.get("1.0", "end").strip()
            prio = cmb_prio.get()
            status = cmb_status.get()
            prazo_txt = ent_prazo.get().strip()

            if not titulo or not desc:
                messagebox.showwarning("Aviso", "Preencha título e descrição.")
                return

            prazo_dt = parse_data_flex(prazo_txt)
            if prazo_txt and not prazo_dt:
                messagebox.showwarning("Aviso", "Data inválida. Use DD/MM/YYYY ou YYYY-MM-DD.")
                return

            criado_em = datetime.now()
            try:
                self.cur.execute("""
                    INSERT INTO tickets (usuario_id, titulo, descricao, prioridade, status, prazo, criado_em)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.usuario[0],
                    titulo,
                    desc,
                    prio,
                    status,
                    formata_data(prazo_dt) if prazo_dt else "",
                    criado_em.strftime("%d/%m/%Y %H:%M")
                ))
                self.conn.commit()
                self._carregar_tickets()
                win.destroy()
                messagebox.showinfo("Sucesso", "Ticket criado com sucesso.")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao salvar: {e}")

        ttk.Button(barra, text="Salvar", command=salvar).pack(side="left", padx=6)
        ttk.Button(barra, text="Cancelar", command=win.destroy).pack(side="left", padx=6)
        frm.columnconfigure(1, weight=1)

    def _exportar_csv(self):
        try:
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                initialfile="tickets.csv",
                title="Salvar CSV"
            )
            if not path:
                return
            self.cur.execute("""
                SELECT id, titulo, descricao, prioridade, status, prazo, criado_em
                FROM tickets WHERE usuario_id=?
            """, (self.usuario[0],))
            rows = self.cur.fetchall()
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["ID", "Título", "Descrição", "Prioridade", "Status", "Prazo", "Criado em"])
                for r in rows:
                    w.writerow(r)
            messagebox.showinfo("Exportar CSV", "Arquivo exportado com sucesso.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar: {e}")

    def _logout(self):
        self.usuario = None
        self.alertados.clear()
        self._montar_tela_login()

    # ---------- Verificador de prazos (thread) ----------
    def _iniciar_verificador_prazos(self):
        t = threading.Thread(target=self._loop_verificacao, daemon=True)
        t.start()

    def _loop_verificacao(self):
        while self.usuario is not None:
            try:
                agora = datetime.now()
                limite = agora + timedelta(hours=24)
                self.cur.execute("""
                    SELECT id, titulo, prazo
                    FROM tickets
                    WHERE usuario_id=? AND (status='Aberto' OR status='Em andamento')
                """, (self.usuario[0],))
                for tid, titulo, prazo_txt in self.cur.fetchall():
                    if not prazo_txt:
                        continue
                    prazo_dt = parse_data_flex(prazo_txt)
                    if not prazo_dt:
                        continue
                    if agora <= prazo_dt <= limite and tid not in self.alertados:
                        self.alertados.add(tid)
                        self.root.after(0, lambda t=titulo, p=prazo_txt: messagebox.showwarning(
                            "Prazo próximo", f'O ticket "{t}" vence em breve (prazo: {p}).'
                        ))
            except Exception:
                pass
            time.sleep(60)

    # ---------- Helpers ----------
    def _limpar_root(self):
        for w in self.root.winfo_children():
            w.destroy()

# ---------------------------- Main ----------------------------
if __name__ == "__main__":
    preparar_banco()
    root = tk.Tk()
    app = App(root)
    root.mainloop()
