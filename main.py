#!/usr/bin/env python3
"""
API FastAPI com Swagger/OpenAPI e Deploy - Template (Nível 2)

Preencha os TODOs seguindo GUIA_APRENDIZADO.md e o exemplo_referencia.py.
Objetivo: adicionar configuração Swagger/OpenAPI e preparar para deploy em produção.

Uso:
    uvicorn template:app --reload --port 8000

Regras:
- Não usar autocomplete/IA para gerar código.
- Manter tempo total em 160min (ver checklist.md).
"""

import os
import uuid
import json
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Dict, List, Literal, Optional

from dotenv import load_dotenv

# LangChain
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage

# Rate Limiter
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# FastAPI
from fastapi import FastAPI, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_404_NOT_FOUND

# Validação
from pydantic import BaseModel, Field

# JWT
from jose import JWTError, jwt

# Hashing
import bcrypt

load_dotenv()

# =============================================================================
# Configuração
# =============================================================================
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise Exception("Favor verificar a JWT_SECRET_KEY")

JWT_ALGORITHM = os.getenv("ALGORITHM")
if not JWT_ALGORITHM:
    raise Exception("Favor verificar o JWT_ALGORITHM")

ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
if not ACCESS_TOKEN_EXPIRE_MINUTES:
    raise Exception("Favor verificar o ACCESS_TOKEN_EXPIRE_MINUTES")

REFRESH_TOKEN_EXPIRE_DAYS = os.getenv("REFRESH_TOKEN_EXPIRE_DAYS")
if not REFRESH_TOKEN_EXPIRE_DAYS:
    raise Exception("Favor verificar o REFRESH_TOKEN_EXPIRE_DAYS")

DEFAULT_MODEL = "gpt-4o-mini"

# Conversações
conversations: Dict[str, Dict[str, List[Dict]]] = {}

app = FastAPI(
    title="Chatbot",
    description="Api de básica de chatbot com rate limiting, log estruturado",
    version="1.0.0",
    contact={
        "name": "Renato Saldanha",
        "email": "ranalisesaldanha@gmail.com",
    },
    license_info={"name": "MIT"}
)

# =============================================================================
# Logging Estruturado
# =============================================================================


class JSONFormatter(logging.Formatter):
    """
    Classe de formatação JSON para o log handler
    """

    def format(self, record):
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Adiciona campos extras
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "conversation_id"):
            log_data["conversation_id"] = record.conversation_id

        return json.dumps(log_data)


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)


def log_structured(level: str, message: str, **kwargs):
    """
    Função helper para logging estruturado.

    Args:
        level: Nível do log (INFO, WARNING, ERROR, etc.)
        message: Mensagem do log
        **kwargs: Campos extras para incluir no log
    """
    # Define o log
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        **kwargs,
    }

    # Converte em string JSON
    log_json = json.dumps(log_data)

    # Verifica o nível do log
    match level:
        case "ERROR":
            logger.error(log_json)
        case "WARNING":
            logger.warning(log_json)
        case "INFO":
            logger.info(log_json)


ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content Security Policy (ajustado para permitir Swagger UI)
        # Para rotas de documentação (/docs, /redoc, /openapi.json), permite CDNs necessários
        if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
            # CSP mais permissivo para Swagger UI (permite CDNs e scripts inline)
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self'"
            )
        else:
            # CSP restritivo para rotas da API
            csp = "default-src 'self'"

        response.headers["Content-Security-Policy"] = csp

        # Strict Transport Security (força HTTPS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Referrer Policy (controla informações enviadas)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions Policy (controla features do navegador)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"

        return response


app.add_middleware(SecurityHeadersMiddleware)


# =============================================================================
# Rate Limiting por Usuário
# =============================================================================

def get_user_id_for_rate_limit(request: Request) -> str:
    """
    Extrai user_id do token JWT para usar como chave de rate limiting.
    Se não houver token, use o IP como fallback.
    """

    # Tentar extrair o header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        # Fallback para IP
        return get_remote_address(request)

    token = auth_header.split(" ")[1]
    try:
        # Decodifica JWT (sem verificar assinatura completa, apenas para extrair user_id)
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        user_id = payload.get("sub")

        return user_id or get_remote_address(request)
    except Exception:
        # Usa IP se falhar
        return get_remote_address(request)


limiter = Limiter(key_func=get_user_id_for_rate_limit)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# =============================================================================
# Exception Handlers Globais
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Trata HTTPException retornando JSON padronizado. 
    """

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url.path),
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Trata erros de validação do Pydantic.
    """

    # define lista de erros
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })

    return JSONResponse(
        status_code=422,
        content={
            "error": True,
            "message": "Erro de validação",
            "errors": errors,
            "status_code": 422,
            "path": str(request.url.path),
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Trata erros inesperados (catch-all).
    """

    logger.error(
        f"Erro inesperado: {exc}",
        exc_info=True,
        extra={
            "path": str(request.url.path),
            "method": request.method,
        }
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Erro interno do servidor",
            "status_code": 500,
            "path": str(request.url.path),
        }
    )


# =============================================================================
# Middleware de Request Logging
# =============================================================================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):

        start_time = time.time()

        # Processa a requisição
        response = await call_next(request)

        duration = time.time() - start_time

        # Efetua log estruturado
        log_structured(
            "INFO",
            "Request processada",
            method=request.method,
            path=str(request.url.path),
            status_code=response.status_code,
            duration_ms=round(duration * 1000, 2),
            client_ip=request.client.host if request.client else None
        )

        return response


app.add_middleware(RequestLoggingMiddleware)


# =============================================================================
# Autenticação (herdado do Dia 4)
# =============================================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def verify_token(token: str, expected_type: str = "access") -> dict:
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        token_type = payload.get("type")
        if token_type != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Tipo de token inválido ({token_type})",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token inválido ou expirado: {exc}",
            headers={"WWW-Authenticate": "Bearer"}
        ) from exc


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = verify_token(token, expected_type="access")
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não autorizado",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return {"username": username, "payload": payload}


# =============================================================================
# Modelos Pydantic
# =============================================================================
# TODO 2: Adicionar descrições e exemplos nos modelos Pydantic
# TODO 2.1: Adicionar Field(description="...") em cada campo
# TODO 2.2: Adicionar Field(example="...") em cada campo quando apropriado
# Dica: Consulte GUIA_APRENDIZADO.md seção 1.5

class Message(BaseModel):
    role: Literal["user", "assistant"] = Field(
        ..., description="Tipo de mensagem", example="assistant")
    content: str = Field(..., description="Conteúdo da mensagem",
                         example="Olá tudo bem?")
    timestamp: Optional[str] = Field(
        default=None, description="Hórario de envio da mensagem")


class ConversationSummary(BaseModel):
    id: str = Field(..., description="ID da conversação",
                    example="11k33h1jjf0591994df-4e93-4902-b04a-7424ebcf05bf")
    created_at: str = Field(..., description="Data de criação")
    last_message: Optional[str] = Field(
        default=None, description="Última mensagem")
    message_count: int = Field(...,
                               description="Quantidade de mensagens na conversação")


class ChatRequest(BaseModel):
    message: str = Field(..., description="Mensagem do usuário")
    conversation_id: Optional[str] = Field(
        None, description="ID da conversa (cria nova se não fornecido)")
    model: Optional[str] = Field(default=None, description="Modelo LLM")
    stream: bool = Field(default=True, description="Se true, responde via SSE")


class Token(BaseModel):
    access_token: str = Field(..., description="Token de acesso")
    refresh_token: str = Field(..., description="Token de atualização")
    token_type: str = Field(default="bearer", description="Tipo de token")


class LoginRequest(BaseModel):
    username: str = Field(..., description="Nome do usuário", example="usu")
    password: str = Field(..., description="Senha do usuário",example="usu123")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(...,
                               description="Token de atualização", example="usu")


class GenerateRequest(BaseModel):
    prompt: str = Field(..., description="Prompt usado nas interações do chat")
    model: Optional[str] = Field(default=None, description="Modelo usado")


# =============================================================================
# Funções auxiliares de histórico (herdado do Dia 4)
# =============================================================================
def get_or_create_conversation(user_id: str, conversation_id: Optional[str] = None) -> str:
    if user_id not in conversations:
        conversations[user_id] = {}
    if conversation_id and conversation_id in conversations[user_id]:
        return conversation_id
    new_id = str(uuid.uuid4())
    conversations[user_id][new_id] = []
    return new_id


def add_message(user_id: str, conversation_id: str, role: str, content: str) -> None:
    if user_id not in conversations:
        conversations[user_id] = {}
    if conversation_id not in conversations[user_id]:
        conversations[user_id][conversation_id] = []
    message = {
        "role": role,
        "content": content,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    conversations[user_id][conversation_id].append(message)


def get_messages(user_id: str, conversation_id: str) -> List[Dict]:
    if user_id not in conversations:
        return []
    if conversation_id not in conversations[user_id]:
        return []
    return conversations[user_id][conversation_id].copy()


def list_conversations(user_id: str) -> List[Dict]:
    if user_id not in conversations:
        return []
    result = []
    for conversation_id, messages in conversations[user_id].items():
        created_at = messages[0].get("timestamp", datetime.now(
            timezone.utc).isoformat()) if messages else None
        last_message = messages[-1].get("content") if messages else None
        message_count = len(messages)
        result.append({
            "id": conversation_id,
            "created_at": created_at,
            "last_message": last_message,
            "message_count": message_count,
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return result


# =============================================================================
# TODO 3: Adicionar Tags aos Endpoints
# =============================================================================
# TODO 3.1: Tag "Auth" para endpoints de autenticação (/login, /refresh)
# TODO 3.2: Tag "Chat" para endpoints de chat (/chat, /conversations, /api/generate)
# TODO 3.3: Tag "Health" para endpoint de health check (/health)
# Dica: Adicione tags=["NomeDaTag"] ao decorator do endpoint
# Dica: Consulte GUIA_APRENDIZADO.md seção 1.4

# =============================================================================
# Endpoints de Autenticação (herdado do Dia 4)
# =============================================================================
FAKE_USER = {
    "username": "admin",
    "hashed_password": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
}


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + \
            timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "type": "access"
    })
    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    time_utc = datetime.now(timezone.utc)
    time_delta = timedelta(days=int(REFRESH_TOKEN_EXPIRE_DAYS))
    expire = time_utc + time_delta
    to_encode.update({
        "exp": expire,
        "type": "refresh",
    })
    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM)
    return encoded_jwt


@app.post("/login", response_model=Token, tags=["Auth"])
@limiter.limit("5/minute")
async def login(
    request: Request, 
    login_data: LoginRequest
    ):
    """
    Autentica um usuário e retorna tokens JWT (access_token e refresh_token)

    **Rate Limiting:** 5 por minuto.

    **Códigos de Resposta:**
    - `200` Login bem-sucedido

    - `401` Credenciais inválidas

    - `422` Erro de validação

    - `429` Limite de requisições excedido
    """
    if login_data.username != FAKE_USER["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário inválido."
        )
    if not bcrypt.checkpw(login_data.password.encode('utf-8'), FAKE_USER["hashed_password"].encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha inválida."
        )
    access_token = create_access_token(data={"sub": login_data.username})
    refresh_token = create_refresh_token(data={"sub": login_data.username})

    log_structured("INFO", "Login bem-sucedido", user_id=login_data.username)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token
    )


@app.post("/refresh", response_model=Token, tags=["Auth"])
async def refresh(request: RefreshRequest):
    """
    Verifica o Token e captura o usuário
    Gera o novo token de acesso e atualização e retorna tokens JWT
    """
    payload = verify_token(request.refresh_token, expected_type="refresh")
    username = payload.get("sub")
    access_token = create_access_token(data={"sub": username})
    refresh_token = create_refresh_token(data={"sub": username})
    return Token(
        access_token=access_token,
        refresh_token=refresh_token)


@app.post("/chat", tags=["Chat"])
@limiter.limit("30/minute")
async def chat(
    request: Request,  # Request deve ser primeiro para slowapi
    chat_request: ChatRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Cria ou retorna um chat existente com base no user_id e conversation_id

    Permitido modelos básicos da OpenAI, caso não for informado non parâmetro será usado o gpt-4o-mini

    Avalia a saída em formato stream com base no parametro stream: True | False

    """
    model_name = chat_request.model or DEFAULT_MODEL
    user_id = current_user["username"]
    conversation_id = get_or_create_conversation(
        user_id, chat_request.conversation_id)

    log_structured(
        "INFO",
        "Inicio de chat",
        user_id=user_id,
        conversation_id=conversation_id,
        model=model_name,
    )

    try:
        messages = get_messages(user_id, conversation_id)
        langchain_messages = []
        for message in messages:
            if message["role"] == "user":
                langchain_messages.append(
                    HumanMessage(content=message["content"]))
            if message["role"] == "assistant":
                langchain_messages.append(
                    AIMessage(content=message["content"]))

        user_message = HumanMessage(content=chat_request.message)
        langchain_messages.append(user_message)
        add_message(user_id, conversation_id, "user", chat_request.message)

        if chat_request.stream:
            async def generate():
                model = ChatOpenAI(
                    model=model_name,
                    temperature=0.2,
                    streaming=True,
                )
                response = ""
                async for chunk in model.astream(langchain_messages):
                    if chunk.content:
                        response += chunk.content
                        yield f"data: {chunk.content}\n\n"
                yield "data: [DONE]\n\n"
                add_message(user_id, conversation_id, "assistant", response)
            return StreamingResponse(generate(), media_type="text/event-stream")
        else:
            model = ChatOpenAI(
                model=model_name,
                temperature=0.2,
                streaming=False,
            )
            ai_response = await model.ainvoke(langchain_messages)
            response_content = ai_response.content
            add_message(user_id, conversation_id,
                        "assistant", response_content)
            return {
                "reply": response_content,
                "conversation_id": conversation_id,
                "user": user_id,
                "model": model_name,
            }
    except Exception as exc:
        log_structured(
            "ERROR",
            "Erro ao processar chat",
            user_id=user_id,
            error=str(exc),
            conversation_id=conversation_id,
        )
        raise


@app.get("/conversations", response_model=List[ConversationSummary], tags=["Chat"])
async def list_user_conversations(
    current_user: dict = Depends(get_current_user),
):
    """
    Retorna uma lista de conversas com base no user_id
    """
    user_id = current_user["username"]
    conversations_list = list_conversations(user_id)
    return [
        ConversationSummary(
            id=conv["id"],
            created_at=conv["created_at"],
            last_message=conv["last_message"],
            message_count=conv["message_count"],
        ) for conv in conversations_list
    ]


@app.get("/conversations/{conversation_id}/messages", response_model=List[Message], tags=["Chat"])
async def get_conversation_messages(
    conversation_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Lista as mensagem de uma conversa pelo conversation_id

    Resposta:

    Array de mensagens com base nnon user_id e conversation_id

    ou

    `404` Not Found para conversas não encontradas
    

    """
    user_id = current_user["username"]
    if user_id not in conversations:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="Conversa não encontrada"
        )
    if conversation_id not in conversations[user_id]:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="Conversa não encontrada"
        )
    messages = get_messages(user_id, conversation_id)
    return [
        Message(
            role=message["role"],
            content=message["content"],
            timestamp=message["timestamp"],
        ) for message in messages
    ]


@app.post("/api/generate", tags=["Chat"])
async def generate(
    request: GenerateRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Gera resposta em tipo Stream com base non prompt informado
    """
    model = request.model or DEFAULT_MODEL
    llm = ChatOpenAI(model=model, streaming=True, temperature=0.2)

    async def generate_stream():
        async for chunk in llm.astream([HumanMessage(content=request.prompt)]):
            if chunk.content:
                yield f"data: {chunk.content}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate_stream(),
        media_type="text/event-stream"
    )


@app.get("/health", tags=["Health"])
async def health():
    """
    Checa se o servidor está rodando.
    """
    return {"status": "healthy", "feature": "rate_limiting_logging"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
