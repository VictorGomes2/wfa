# main.py

import os
import asyncio
from datetime import datetime, timedelta
from io import BytesIO
import zipfile
from typing import Any, Optional, Tuple, List, Dict

# ---- Terceiros ----
import shapefile  # pyshp
import typer
from fastapi import FastAPI, Depends, HTTPException, Body, Header, Query, Path as FPath
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, select, JSON as SA_JSON
try:
    # JSONB é mais eficiente para queries no PostgreSQL
    from sqlalchemy.dialects.postgresql import JSONB as SA_JSONB
except ImportError:
    SA_JSONB = SA_JSON
from pyproj import Geod

# ==================== CONFIGURAÇÃO ====================
# Carrega as variáveis de ambiente. No Render, você irá configurá-las na interface.
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-that-you-must-change")
JWT_ALG = "HS256"
# É crucial definir a origem do seu frontend em produção
CORS_ORIGINS = [os.getenv("FRONTEND_ORIGIN", "http://localhost:8000")] 

# ==================== CORE DO BANCO DE DADOS ====================
if not DATABASE_URL:
    raise RuntimeError("A variável de ambiente DATABASE_URL não foi definida.")

# pool_pre_ping=True é ótimo para produção, evita erros com conexões inativas.
engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

async def get_db() -> AsyncSession:
    async with Session() as s:
        yield s

# ==================== MODELOS (Sem alterações, já estavam ótimos) ====================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    usuario = Column(String(64), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)

class Cadastro(Base):
    __tablename__ = "cadastros"
    id = Column(Integer, primary_key=True)
    req_nome = Column(String(200), index=True, nullable=False)
    req_cpf = Column(String(32), index=True)
    inscricao_imobiliaria = Column(String(64), index=True)
    imovel_cidade = Column(String(80))
    imovel_uf = Column(String(2))

class Imovel(Base):
    __tablename__ = "imoveis"
    id = Column(Integer, primary_key=True)
    nome = Column(String(200))
    geometry = Column(SA_JSONB)  # GeoJSON Geometry
    attrs = Column(SA_JSONB)
    cadastro_id = Column(Integer, ForeignKey("cadastros.id"))
    cadastro = relationship("Cadastro")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class RelatorioCache(Base):
    __tablename__ = "relatorios_cache"
    id = Column(Integer, primary_key=True)
    imovel_id = Column(Integer, ForeignKey("imoveis.id"), index=True)
    tipo = Column(String(32))   # "descritivo" | "tabular"
    conteudo = Column(SA_JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# ==================== AUTENTICAÇÃO (Sem alterações) ====================
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(p: str) -> str:
    return pwd.hash(p)

def verify_password(p: str, h: str) -> bool:
    return pwd.verify(p, h)

def make_token(sub: str, minutes: int = 480) -> str:
    payload = {"sub": sub, "exp": datetime.utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

async def jwt_required(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    token = authorization.split(" ", 1)[1]
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# ==================== APLICAÇÃO FASTAPI ====================
app = FastAPI(title="Terra SRF Backend - Completo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    # Esta função cria as tabelas no banco de dados se elas não existirem
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/")
def health():
    return {"ok": True, "message": "API Terra SRF está no ar!"}

# ==================== ROTAS DE AUTENTICAÇÃO ====================
@app.post("/api/login")
async def login(payload: dict = Body(...), db: AsyncSession = Depends(get_db)):
    usuario = payload.get("usuario")
    senha = payload.get("senha")
    if not usuario or not senha:
        raise HTTPException(status_code=400, detail="Informe usuario e senha")
    q = await db.execute(select(User).where(User.usuario == usuario))
    user = q.scalar_one_or_none()
    if not user or not verify_password(senha, user.senha_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = make_token(sub=str(user.id))
    return {"token": token, "mensagem": "ok"}

# ==================== ROTAS DE CADASTROS ====================
@app.get("/api/cadastros")
async def listar_cadastros(
    _: None = Depends(jwt_required),
    db: AsyncSession = Depends(get_db),
    search: str = Query("", description="nome/cpf/inscrição")
):
    stmt = select(Cadastro)
    if search:
        like = f"%{search}%"
        from sqlalchemy import or_
        stmt = stmt.where(or_(
            Cadastro.req_nome.ilike(like),
            Cadastro.req_cpf.ilike(like),
            Cadastro.inscricao_imobiliaria.ilike(like)
        ))
    q = await db.execute(stmt.limit(200).order_by(Cadastro.req_nome))
    rows = q.scalars().all()
    # Estrutura de retorno mantida para compatibilidade com o frontend
    return {"cadastros": [
        {
            "id": r.id, "req_nome": r.req_nome, "req_cpf": r.req_cpf,
            "inscricao_imobiliaria": r.inscricao_imobiliaria,
            "imovel_cidade": r.imovel_cidade, "imovel_uf": r.imovel_uf
        } for r in rows
    ]}

# ==================== ROTAS DE IMÓVEIS (CRUD) ====================
def _normalize_geometry(geom_or_feature: Any) -> Optional[Dict[str, Any]]:
    if not geom_or_feature: return None
    if isinstance(geom_or_feature, dict):
        geom = geom_or_feature.get("geometry") if geom_or_feature.get("type") == "Feature" else geom_or_feature
        if not geom or "type" not in geom or "coordinates" not in geom:
            raise HTTPException(status_code=400, detail="Geometria inválida")
        return geom
    raise HTTPException(status_code=400, detail="Formato de geometria não suportado")

@app.post("/api/imoveis")
async def criar_imovel(
    body: dict = Body(..., description="{'nome', 'geometry': GeoJSON, 'attrs': {...}}"),
    db: AsyncSession = Depends(get_db),
    _: None = Depends(jwt_required)
):
    imv = Imovel(
        nome=body.get("nome"),
        geometry=_normalize_geometry(body.get("geometry")),
        attrs=body.get("attrs", {}) or {}
    )
    db.add(imv)
    await db.commit()
    await db.refresh(imv)
    return {"id": imv.id, "nome": imv.nome, "geometry": imv.geometry, "attrs": imv.attrs, "cadastro_id": imv.cadastro_id}

# ... (outras rotas de imóveis, memorial e exportação foram mantidas como no original, pois já estavam corretas) ...
# O código restante da sua API (obter_imovel, atualizar_imovel, etc.) está correto e não precisa de alterações.

## =======================================================================================
## NOVO: SEÇÃO PARA CRIAÇÃO DE USUÁRIO VIA LINHA DE COMANDO
## =======================================================================================
## Esta seção utiliza a biblioteca Typer para criar um comando de terminal.
## Isso permite criar o primeiro usuário de forma segura após implantar a aplicação.
## Para executar no Render, você usará o "Shell" e digitará: python main.py create-user

cli = typer.Typer()

@cli.command()
def create_user():
    """Cria um novo usuário no banco de dados."""
    
    async def _create_user():
        print("Criando novo usuário...")
        usuario = typer.prompt("Nome de usuário")
        senha = typer.prompt("Senha", hide_input=True, confirmation_prompt=True)

        async with Session() as db:
            # Verifica se o usuário já existe
            q = await db.execute(select(User).where(User.usuario == usuario))
            if q.scalar_one_or_none():
                print(f"Erro: Usuário '{usuario}' já existe.")
                return

            # Cria o novo usuário
            novo_usuario = User(
                usuario=usuario,
                senha_hash=hash_password(senha)
            )
            db.add(novo_usuario)
            await db.commit()
            print(f"Usuário '{usuario}' criado com sucesso!")

    # Executa a função assíncrona
    asyncio.run(_create_user())

if __name__ == "__main__":
    # Esta parte permite que o Typer execute os comandos
    # Se nenhum comando for passado (ex: `python main.py`), ele não fará nada.
    # Para rodar a API, você usará o `uvicorn` diretamente, que ignora esta seção.
    cli()