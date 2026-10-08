
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from datetime import date
import fdb

app = Flask(__name__)
app.secret_key = 'automatic_fit'
bcrypt = Bcrypt(app)


# BANCO DE DADOS

def conectar():
    return fdb.connect(
        host='localhost',
        database=r'C:\Users\Aluno\Downloads\projetofit\BANCO.FDB',
        user='sysdba',
        password='sysdba'
    )


# SENHA FORTE

def senha_forte(senha):
    return (
        len(senha) >= 8
        and any(c.isupper() for c in senha)
        and any(c.islower() for c in senha)
        and any(c.isdigit() for c in senha)
    )


# USUÁRIOS INICIAIS

def criar_usuarios_iniciais():
    contas = [
        ('Administrador', 'adm@automaticfit.com', 'Admin@123', 'ADMINISTRADOR'),
        ('Professor', 'professor@automaticfit.com', 'Professor@123', 'PERSONAL'),
        ('Aluno', 'aluno@automaticfit.com', 'Aluno@123', 'ALUNO')
    ]

    con = conectar()

    try:
        cursor = con.cursor()

        for nome, email, senha, tipo in contas:
            cursor.execute(
                'SELECT 1 FROM USUARIOS WHERE EMAIL = ?', (email,)
            )

            if cursor.fetchone():
                continue

            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

            cursor.execute('''
                INSERT INTO USUARIOS (NOME, EMAIL, SENHA, TIPO_USUARIO)
                VALUES (?, ?, ?, ?)
                RETURNING ID_USUARIO
            ''', (nome, email, senha_hash, tipo))

            id_usuario = cursor.fetchone()[0]

            cursor.execute('''
                INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                VALUES (?, ?)
            ''', (id_usuario, senha_hash))

        con.commit()

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()


# LANDING PAGE

@app.route('/')
def index():
    return render_template('landing.html')


# CADASTRO

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome'].strip()
        email = request.form['email'].strip().lower()
        telefone = request.form.get('telefone', '').strip()
        cpf = ''.join(c for c in request.form['cpf'] if c.isdigit())
        senha = request.form['senha']
        confirmar = request.form['confirmar_senha']

        try:
            nascimento = date.fromisoformat(request.form['data_nascimento'])
        except ValueError:
            flash('Data de nascimento inválida.')
            return redirect(url_for('cadastro'))

        if not nome or not email:
            flash('Preencha nome e e-mail.')
            return redirect(url_for('cadastro'))

        if len(cpf) != 11:
            flash('O CPF deve conter 11 números.')
            return redirect(url_for('cadastro'))

        if nascimento > date.today():
            flash('Data de nascimento inválida.')
            return redirect(url_for('cadastro'))

        if senha != confirmar:
            flash('As senhas não coincidem.')
            return redirect(url_for('cadastro'))

        if not senha_forte(senha):
            flash('A senha deve ter 8 caracteres, maiúscula, minúscula e número.')
            return redirect(url_for('cadastro'))

        con = conectar()

        try:
            cursor = con.cursor()
            cursor.execute(
                'SELECT 1 FROM USUARIOS WHERE EMAIL = ?', (email,)
            )

            if cursor.fetchone():
                flash('E-mail já cadastrado.')
                return redirect(url_for('cadastro'))

            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

            cursor.execute('''
                INSERT INTO USUARIOS
                (NOME, EMAIL, SENHA, TIPO_USUARIO,
                 TELEFONE, CPF, DATA_NASCIMENTO)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                RETURNING ID_USUARIO
            ''', (nome, email, senha_hash, 'ALUNO',
                  telefone, cpf, nascimento))

            id_usuario = cursor.fetchone()[0]

            cursor.execute('''
                INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                VALUES (?, ?)
            ''', (id_usuario, senha_hash))

            con.commit()
            flash('Cadastro realizado com sucesso!')
            return redirect(url_for('login'))

        except Exception as e:
            con.rollback()
            print(e)
            flash('Erro ao cadastrar usuário.')

        finally:
            con.close()

    return render_template('cadastro.html')


# LOGIN ÚNICO

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        senha = request.form['senha']

        con = conectar()

        try:
            cursor = con.cursor()
            cursor.execute('''
                SELECT ID_USUARIO, NOME, SENHA, TIPO_USUARIO,
                       TENTATIVAS_LOGIN, BLOQUEADO, ATIVO
                FROM USUARIOS
                WHERE EMAIL = ?
            ''', (email,))

            usuario = cursor.fetchone()

            if not usuario:
                flash('E-mail ou senha incorretos.')
                return redirect(url_for('login'))

            id_usuario, nome, senha_hash, tipo, tentativas, bloqueado, ativo = usuario

            if ativo == 0:
                flash('Usuário inativo.')
                return redirect(url_for('login'))

            if bloqueado == 1:
                flash('Usuário bloqueado.')
                return redirect(url_for('login'))

            if bcrypt.check_password_hash(senha_hash, senha):
                rotas = {
                    'ALUNO': 'aluno',
                    'PERSONAL': 'personal',
                    'ADMINISTRADOR': 'administrador'
                }

                if tipo not in rotas:
                    flash('Perfil inválido.')
                    return redirect(url_for('login'))

                cursor.execute('''
                    UPDATE USUARIOS
                    SET TENTATIVAS_LOGIN = 0
                    WHERE ID_USUARIO = ?
                ''', (id_usuario,))

                con.commit()

                session.clear()
                session['id_usuario'] = id_usuario
                session['nome_usuario'] = nome
                session['tipo_usuario'] = tipo

                return redirect(url_for(rotas[tipo]))

            tentativas += 1
            bloqueado = 1 if tentativas >= 3 else 0

            cursor.execute('''
                UPDATE USUARIOS
                SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                WHERE ID_USUARIO = ?
            ''', (tentativas, bloqueado, id_usuario))

            con.commit()

            if bloqueado:
                flash('Usuário bloqueado após 3 tentativas.')
            else:
                flash(f'Senha incorreta. Restam {3 - tentativas} tentativas.')

        except Exception as e:
            con.rollback()
            print(e)
            flash('Erro ao realizar login.')

        finally:
            con.close()

        return redirect(url_for('login'))

    return render_template('login.html')


# VERIFICAR SESSÃO

def acesso_valido(tipo):
    id_usuario = session.get('id_usuario')

    if not id_usuario:
        return False

    con = conectar()

    try:
        cursor = con.cursor()
        cursor.execute('''
            SELECT NOME, TIPO_USUARIO, ATIVO, BLOQUEADO
            FROM USUARIOS
            WHERE ID_USUARIO = ?
        ''', (id_usuario,))

        usuario = cursor.fetchone()

        if not usuario or usuario[2] == 0 or usuario[3] == 1:
            session.clear()
            return False

        if usuario[1] != session.get('tipo_usuario'):
            session.clear()
            return False

        if usuario[1] != tipo:
            return False

        session['nome_usuario'] = usuario[0]
        return True

    finally:
        con.close()


# HOME PROTEGIDA

def abrir_home(tipo):
    if not acesso_valido(tipo):
        return redirect(url_for('login'))

    return render_template(
        'home.html',
        usuario=session['nome_usuario'],
        perfil=tipo
    )


@app.route('/aluno')
def aluno():
    return abrir_home('ALUNO')


@app.route('/personal')
def personal():
    return abrir_home('PERSONAL')


@app.route('/administrador')
def administrador():
    return abrir_home('ADMINISTRADOR')


# LISTAR USUÁRIOS

@app.route('/usuarios')
def usuarios():
    if not acesso_valido('ADMINISTRADOR'):
        return redirect(url_for('login'))

    con = conectar()

    try:
        cursor = con.cursor()
        cursor.execute('''
            SELECT ID_USUARIO, NOME, EMAIL, TIPO_USUARIO,
                   ATIVO, BLOQUEADO
            FROM USUARIOS
            ORDER BY NOME
        ''')

        lista = cursor.fetchall()

        return render_template('usuarios.html', usuarios=lista)

    finally:
        con.close()


# EDITAR USUÁRIO

@app.route('/editar_usuario/<int:id_usuario>', methods=['GET', 'POST'])
def editar_usuario(id_usuario):
    if not acesso_valido('ADMINISTRADOR'):
        return redirect(url_for('login'))

    con = conectar()

    try:
        cursor = con.cursor()
        cursor.execute('''
            SELECT ID_USUARIO, NOME, EMAIL, TIPO_USUARIO,
                   TELEFONE, CPF, DATA_NASCIMENTO,
                   TENTATIVAS_LOGIN, BLOQUEADO, ATIVO
            FROM USUARIOS
            WHERE ID_USUARIO = ?
        ''', (id_usuario,))

        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuário não encontrado.')
            return redirect(url_for('usuarios'))

        if request.method == 'POST':
            nome = request.form['nome'].strip()
            email = request.form['email'].strip().lower()
            telefone = request.form.get('telefone', '').strip()
            cpf = ''.join(c for c in request.form.get('cpf', '') if c.isdigit())
            tipo = request.form['tipo_usuario']
            senha = request.form.get('senha', '')

            tentativas = int(request.form['tentativas_login'])
            bloqueado = int(request.form['bloqueado'])
            ativo = int(request.form['ativo'])

            nascimento_texto = request.form.get('data_nascimento', '')
            nascimento = date.fromisoformat(nascimento_texto) if nascimento_texto else None

            if not nome or not email:
                flash('Nome e e-mail são obrigatórios.')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            if tipo not in ('ALUNO', 'PERSONAL', 'ADMINISTRADOR'):
                flash('Perfil inválido.')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            if (cpf and len(cpf) != 11) or tentativas < 0:
                flash('CPF ou tentativas de login inválidos.')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            if ativo not in (0, 1) or bloqueado not in (0, 1):
                flash('Status inválido.')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            if nascimento and nascimento > date.today():
                flash('Data de nascimento inválida.')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            cursor.execute('''
                SELECT 1 FROM USUARIOS
                WHERE EMAIL = ? AND ID_USUARIO <> ?
            ''', (email, id_usuario))

            if cursor.fetchone():
                flash('E-mail já cadastrado.')
                return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            if senha:
                if not senha_forte(senha):
                    flash('A senha deve ter 8 caracteres, maiúscula, minúscula e número.')
                    return redirect(url_for('editar_usuario', id_usuario=id_usuario))

                cursor.execute('''
                    SELECT SENHA FROM USUARIOS WHERE ID_USUARIO = ?
                ''', (id_usuario,))
                senha_atual = cursor.fetchone()[0]

                cursor.execute('''
                    SELECT FIRST 3 SENHA FROM HISTORICO_SENHAS
                    WHERE ID_USUARIO = ?
                    ORDER BY ID_HISTORICO DESC
                ''', (id_usuario,))

                historico = [senha_atual] + [linha[0] for linha in cursor.fetchall()]

                if any(bcrypt.check_password_hash(h, senha) for h in historico):
                    flash('Não é permitido reutilizar uma das 3 últimas senhas.')
                    return redirect(url_for('editar_usuario', id_usuario=id_usuario))

            cursor.execute('''
                UPDATE USUARIOS
                SET NOME = ?, EMAIL = ?, TIPO_USUARIO = ?,
                    TELEFONE = ?, CPF = ?, DATA_NASCIMENTO = ?,
                    TENTATIVAS_LOGIN = ?, BLOQUEADO = ?, ATIVO = ?
                WHERE ID_USUARIO = ?
            ''', (nome, email, tipo, telefone, cpf or None, nascimento,
                  tentativas, bloqueado, ativo, id_usuario))

            if senha:
                senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

                cursor.execute('''
                    UPDATE USUARIOS SET SENHA = ?
                    WHERE ID_USUARIO = ?
                ''', (senha_hash, id_usuario))

                cursor.execute('''
                    INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                    VALUES (?, ?)
                ''', (id_usuario, senha_hash))

            con.commit()

            flash('Usuário atualizado com sucesso!')

            if session['id_usuario'] == id_usuario:
                session['nome_usuario'] = nome

                if tipo != 'ADMINISTRADOR' or ativo == 0 or bloqueado == 1:
                    session.clear()
                    return redirect(url_for('login'))

            return redirect(url_for('usuarios'))

        return render_template('editar_usuario.html', usuario=usuario)

    except (ValueError, KeyError):
        con.rollback()
        flash('Verifique os campos informados.')
        return redirect(url_for('editar_usuario', id_usuario=id_usuario))

    except Exception as e:
        con.rollback()
        print(e)
        flash('Erro ao editar usuário.')
        return redirect(url_for('usuarios'))

    finally:
        con.close()


# LOGOUT

@app.route('/logout')
def logout():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    session.clear()
    return redirect(url_for('login'))


# EXECUTAR

if __name__ == '__main__':
    criar_usuarios_iniciais()
    app.run(debug=True)


