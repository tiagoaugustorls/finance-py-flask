from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from collections import defaultdict
import matplotlib.pyplot as plt
import io
import base64
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

app = Flask(__name__)

# Configuração do banco de dados (usando SQLite como exemplo)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)

db = SQLAlchemy(app)

# ------------------------
# MODELOS
# ------------------------

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

    def __repr__(self):
        return f"Usuario('{self.nome}', '{self.email}')"

class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(200), nullable=False)
    data_hora = db.Column(db.DateTime, nullable=False, default=datetime.now)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

# ------------------------
# DECORADORES
# ------------------------

def login_requerido(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------------
# ROTAS
# ------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('conta', user_id=session['user_id']))
    return render_template('index.html')

@app.route('/conta', methods=['GET'])
@login_requerido
def conta():
    user_id = request.args.get('user_id')
    if int(user_id) != session['user_id']:
        flash('Você não tem permissão para acessar esta conta.', 'danger')
        return redirect(url_for('conta', user_id=session['user_id']))

    usuario = Usuario.query.get_or_404(user_id)
    transacoes = Transacao.query.filter_by(usuario_id=user_id).all()
    
    total_receitas = 0
    total_despesas = 0
    
    for transacao in transacoes:
        if transacao.valor and isinstance(transacao.valor, (int, float)):
            if transacao.tipo == 'receita':
                total_receitas += transacao.valor
            elif transacao.tipo == 'despesa':
                total_despesas += transacao.valor
    
    total_receitas = total_receitas if total_receitas is not None else 0
    total_despesas = total_despesas if total_despesas is not None else 0

    # Inicializa graph_url como None
    graph_url = None

    # Só gera o gráfico se houver algum valor positivo
    if total_receitas > 0 or total_despesas > 0:
        fig, ax = plt.subplots()
        ax.pie(
            [total_receitas, total_despesas],
            labels=['Receitas', 'Despesas'],
            autopct='%1.1f%%',
            colors=['green', 'red']
        )
        ax.axis('equal')

        output = io.BytesIO()
        FigureCanvas(fig).print_png(output)
        graph_url = base64.b64encode(output.getvalue()).decode('utf8')

    return render_template('user_account.html', usuario=usuario, transacoes=transacoes, graph_url=graph_url)


@app.route('/adicionar_transacao/<int:user_id>', methods=['GET', 'POST'])
@login_requerido
def adicionar_transacao(user_id):
    if int(user_id) != session['user_id']:
        flash('Você não tem permissão para realizar esta ação.', 'danger')
        return redirect(url_for('conta', user_id=session['user_id']))

    usuario = Usuario.query.get_or_404(user_id)
    if request.method == 'POST':
        tipo = request.form['tipo']
        valor = float(request.form['valor'])
        descricao = request.form['descricao']
        nova_transacao = Transacao(tipo=tipo, valor=valor, descricao=descricao, usuario_id=user_id)
        db.session.add(nova_transacao)
        db.session.commit()
        flash('Transação adicionada com sucesso!', 'success')
        return redirect(url_for('conta', user_id=user_id))
    return render_template('adicionar_transacao.html', usuario=usuario)

@app.route('/deletar_transacao/<int:transacao_id>/<int:user_id>', methods=['POST'])
@login_requerido
def deletar_transacao(transacao_id, user_id):
    if int(user_id) != session['user_id']:
        flash('Você não tem permissão para realizar esta ação.', 'danger')
        return redirect(url_for('conta', user_id=session['user_id']))

    transacao = Transacao.query.get_or_404(transacao_id)
    db.session.delete(transacao)
    db.session.commit()
    flash('Transação excluída com sucesso!', 'success')
    return redirect(url_for('conta', user_id=user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and usuario.verificar_senha(senha):
            session['user_id'] = usuario.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('conta', user_id=usuario.id))
        else:
            flash('Email ou senha incorretos. Tente novamente.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Você saiu da sua conta com sucesso.', 'info')
    return redirect(url_for('login'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']

        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('Email já cadastrado. Por favor, use outro email.', 'danger')
            return redirect(url_for('cadastro'))

        if senha != confirmar_senha:
            flash('As senhas não coincidem. Tente novamente.', 'danger')
            return redirect(url_for('cadastro'))

        novo_usuario = Usuario(nome=nome, email=email)
        novo_usuario.set_senha(senha)
        db.session.add(novo_usuario)
        db.session.commit()
        flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))

    return render_template('cadastro.html')

# ------------------------
# EXECUÇÃO
# ------------------------

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
