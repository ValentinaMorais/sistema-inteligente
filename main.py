import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import bcrypt
import datetime
import base64

# Função para criar estilo moderno no ttk
def criar_estilo():
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TButton",
                    font=('Segoe UI', 11, 'bold'),
                    background='#4CAF50',
                    foreground='white',
                    padding=8)
    style.map("TButton",
              background=[('active', '#45a049')],
              foreground=[('active', 'white')])
    style.configure("TLabel",
                    font=('Segoe UI', 10))
    style.configure("Treeview",
                    font=('Segoe UI', 10),
                    rowheight=28,
                    background='white',
                    fieldbackground='white',
                    foreground='black')
    style.configure("Treeview.Heading",
                    font=('Segoe UI', 11, 'bold'),
                    background='#4CAF50',
                    foreground='white')
    style.map('Treeview', background=[('selected', '#347083')])

class TicketSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema Inteligente de Tickets")
        self.root.geometry("900x600")
        self.root.resizable(False, False)
        criar_estilo()

        self.conn = sqlite3.connect('tickets.db')
        self.cursor = self.conn.cursor()
        self.criar_tabelas()

        # Frames principais
        self.frame_login = ttk.Frame(root, padding=30)
        self.frame_tickets = ttk.Frame(root, padding=20)

        self.usuario_logado = None

        self.build_login_frame()
        self.build_tickets_frame()

        self.frame_login.pack(expand=True)

    def criar_tabelas(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                titulo TEXT NOT NULL,
                descricao TEXT NOT NULL,
                prioridade TEXT NOT NULL,
                status TEXT NOT NULL,
                criado_em TEXT NOT NULL,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            )
        ''')
        self.conn.commit()

    def build_login_frame(self):
        for widget in self.frame_login.winfo_children():
            widget.destroy()

        ttk.Label(self.frame_login, text="Login no Sistema de Tickets", font=('Segoe UI', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=20)

        ttk.Label(self.frame_login, text="Usuário:").grid(row=1, column=0, sticky='e', padx=10, pady=10)
        self.usuario_entry = ttk.Entry(self.frame_login, width=30)
        self.usuario_entry.grid(row=1, column=1, pady=10)
        self.usuario_entry.focus()
        self.usuario_entry.bind('<Return>', lambda e: self.login())

        ttk.Label(self.frame_login, text="Senha:").grid(row=2, column=0, sticky='e', padx=10, pady=10)
        self.senha_entry = ttk.Entry(self.frame_login, show='*', width=30)
        self.senha_entry.grid(row=2, column=1, pady=10)
        self.senha_entry.bind('<Return>', lambda e: self.login())

        btn_login = ttk.Button(self.frame_login, text="Entrar", command=self.login)
        btn_login.grid(row=3, column=0, columnspan=2, pady=15, ipadx=10)

        btn_registrar = ttk.Button(self.frame_login, text="Registrar Novo Usuário", command=self.registrar)
        btn_registrar.grid(row=4, column=0, columnspan=2, pady=5, ipadx=10)

    def login(self):
        user = self.usuario_entry.get().strip()
        pwd = self.senha_entry.get().strip()
        if not user or not pwd:
            messagebox.showwarning("Aviso", "Preencha usuário e senha.")
            return
        self.cursor.execute("SELECT id, senha FROM usuarios WHERE usuario=?", (user,))
        resultado = self.cursor.fetchone()
        if resultado:
            usuario_id, senha_b64 = resultado
            try:
                senha_hash = base64.b64decode(senha_b64)
                if bcrypt.checkpw(pwd.encode('utf-8'), senha_hash):
                    self.usuario_logado = (usuario_id, user)
                    self.frame_login.pack_forget()
                    self.frame_tickets.pack(fill='both', expand=True)
                    self.usuario_label.config(text=f"Usuário: {user}")
                    self.atualizar_tabela()
                    return
                else:
                    messagebox.showerror("Erro", "Senha incorreta.")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao validar a senha: {e}")
        else:
            messagebox.showerror("Erro", "Usuário não encontrado.")

    def registrar(self):
        user = self.usuario_entry.get().strip()
        pwd = self.senha_entry.get().strip()
        if not user or not pwd:
            messagebox.showwarning("Aviso", "Usuário e senha não podem ser vazios.")
            return
        self.cursor.execute("SELECT id FROM usuarios WHERE usuario=?", (user,))
        if self.cursor.fetchone():
            messagebox.showerror("Erro", "Usuário já existe.")
            return
        hash_bytes = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
        hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
        self.cursor.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", (user, hash_b64))
        self.conn.commit()
        messagebox.showinfo("Sucesso", "Usuário registrado com sucesso.")

    def build_tickets_frame(self):
        for widget in self.frame_tickets.winfo_children():
            widget.destroy()

        top_frame = ttk.Frame(self.frame_tickets)
        top_frame.pack(fill='x')

        self.usuario_label = ttk.Label(top_frame, text="Usuário: ", font=('Segoe UI', 12, 'bold'))
        self.usuario_label.pack(side='left')

        btn_sair = ttk.Button(top_frame, text="Sair", command=self.logout)
        btn_sair.pack(side='right')

        btn_novo = ttk.Button(self.frame_tickets, text="Novo Ticket", command=self.novo_ticket)
        btn_novo.pack(pady=15)

        colunas = ("ID", "Título", "Descrição", "Prioridade", "Status", "Criado em")
        self.tree = ttk.Treeview(self.frame_tickets, columns=colunas, show='headings')
        for col in colunas:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor='center')

        self.tree.pack(fill='both', expand=True)

        # Cores para prioridades
        self.tree.tag_configure('Alta', background='#ff6b6b')    # Vermelho claro
        self.tree.tag_configure('Média', background='#ffd93b')   # Amarelo
        self.tree.tag_configure('Baixa', background='#6bcB77')   # Verde claro

    def atualizar_tabela(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.cursor.execute("""
            SELECT id, titulo, descricao, prioridade, status, criado_em
            FROM tickets WHERE usuario_id=?
            ORDER BY criado_em DESC
        """, (self.usuario_logado[0],))
        for row in self.cursor.fetchall():
            self.tree.insert('', 'end', values=row, tags=(row[3],))

    def novo_ticket(self):
        self.janela_ticket = tk.Toplevel(self.root)
        self.janela_ticket.title("Novo Ticket")
        self.janela_ticket.geometry("450x350")
        self.janela_ticket.resizable(False, False)

        ttk.Label(self.janela_ticket, text="Título:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, padx=10, pady=10, sticky='e')
        titulo_entry = ttk.Entry(self.janela_ticket, width=40)
        titulo_entry.grid(row=0, column=1, padx=10, pady=10)
        titulo_entry.focus()

        ttk.Label(self.janela_ticket, text="Descrição:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, padx=10, pady=10, sticky='ne')
        descricao_text = tk.Text(self.janela_ticket, width=30, height=6, font=('Segoe UI', 10))
        descricao_text.grid(row=1, column=1, padx=10, pady=10)

        ttk.Label(self.janela_ticket, text="Prioridade:", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, padx=10, pady=10, sticky='e')
        prioridade_combo = ttk.Combobox(self.janela_ticket, values=["Alta", "Média", "Baixa"], state="readonly", width=37)
        prioridade_combo.grid(row=2, column=1, padx=10, pady=10)
        prioridade_combo.current(1)

        ttk.Label(self.janela_ticket, text="Status:", font=('Segoe UI', 10, 'bold')).grid(row=3, column=0, padx=10, pady=10, sticky='e')
        status_combo = ttk.Combobox(self.janela_ticket, values=["Aberto", "Em andamento", "Fechado"], state="readonly", width=37)
        status_combo.grid(row=3, column=1, padx=10, pady=10)
        status_combo.current(0)

        def salvar():
            titulo = titulo_entry.get().strip()
            descricao = descricao_text.get("1.0", "end").strip()
            prioridade = prioridade_combo.get()
            status = status_combo.get()
            if not titulo or not descricao:
                messagebox.showwarning("Aviso", "Preencha título e descrição.")
                return
            criado_em = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
            self.cursor.execute('''
                INSERT INTO tickets (usuario_id, titulo, descricao, prioridade, status, criado_em)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (self.usuario_logado[0], titulo, descricao, prioridade, status, criado_em))
            self.conn.commit()
            self.atualizar_tabela()
            self.janela_ticket.destroy()
            messagebox.showinfo("Sucesso", "Ticket criado com sucesso!")

        btn_salvar = ttk.Button(self.janela_ticket, text="Salvar Ticket", command=salvar)
        btn_salvar.grid(row=4, column=0, columnspan=2, pady=15, ipadx=20)

    def logout(self):
        self.usuario_logado = None
        self.frame_tickets.pack_forget()
        self.usuario_entry.delete(0, 'end')
        self.senha_entry.delete(0, 'end')
        self.frame_login.pack(expand=True)


if __name__ == "__main__":
    root = tk.Tk()
    app = TicketSystem(root)
    root.mainloop()
