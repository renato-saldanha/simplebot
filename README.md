# SimpleBot - API de Chatbot com FastAPI

API REST desenvolvida em FastAPI para criação de chatbots inteligentes utilizando modelos de linguagem da OpenAI através do LangChain.

## 🚀 Funcionalidades

- **Chat Inteligente**: Integração com modelos OpenAI (GPT-4o-mini, GPT-4, etc.) via LangChain
- **Autenticação JWT**: Sistema de autenticação com tokens de acesso e refresh
- **Gerenciamento de Conversas**: Criação e gerenciamento de múltiplas conversas por usuário
- **Streaming de Respostas**: Suporte a Server-Sent Events (SSE) para respostas em tempo real
- **Rate Limiting**: Controle de taxa de requisições por usuário
- **Logging Estruturado**: Sistema de logs em formato JSON para facilitar monitoramento
- **Documentação Interativa**: Swagger/OpenAPI integrado para testes e documentação
- **Segurança**: Middlewares de segurança com headers HTTP e CORS configurado

## 📋 Pré-requisitos

- Python 3.8+
- Conta OpenAI com API key

## 🔧 Instalação

1. Clone o repositório:
```bash
git clone <url-do-repositorio>
cd simplebot
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Configure as variáveis de ambiente criando um arquivo `.env`:
```env
OPENAI_API_KEY=sua_chave_openai_aqui
JWT_SECRET_KEY=sua_chave_secreta_jwt
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

## 🏃 Executando

Para iniciar o servidor em modo de desenvolvimento:

```bash
uvicorn main:app --reload --port 8000
```

A API estará disponível em `http://localhost:8000`

## 📚 Documentação

Após iniciar o servidor, acesse:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

## 🔌 Endpoints Principais

### Autenticação
- `POST /login` - Autenticação de usuário (retorna access_token e refresh_token)
- `POST /refresh` - Renovação de tokens

### Chat
- `POST /chat` - Enviar mensagem e receber resposta do chatbot
- `GET /conversations` - Listar todas as conversas do usuário
- `GET /conversations/{conversation_id}/messages` - Obter mensagens de uma conversa específica
- `POST /api/generate` - Gerar resposta baseada em prompt (streaming)

### Utilitários
- `GET /health` - Verificar status da API

## 🔐 Autenticação

A API utiliza autenticação JWT Bearer Token. Para acessar endpoints protegidos:

1. Faça login em `/login` com as credenciais:
   - Username: `admin`
   - Password: `admin123`

2. Use o `access_token` retornado no header das requisições:
```
Authorization: Bearer <access_token>
```

## 💻 Exemplo de Uso

### Criar uma conversa e enviar mensagem:

```python
import requests

# 1. Login
login_response = requests.post("http://localhost:8000/login", json={
    "username": "admin",
    "password": "admin123"
})
tokens = login_response.json()
access_token = tokens["access_token"]

# 2. Enviar mensagem
headers = {"Authorization": f"Bearer {access_token}"}
chat_response = requests.post(
    "http://localhost:8000/chat",
    json={
        "message": "Olá, como você pode me ajudar?",
        "stream": False
    },
    headers=headers
)
print(chat_response.json())
```

## 🛠️ Tecnologias Utilizadas

- **FastAPI**: Framework web moderno e rápido
- **LangChain**: Framework para aplicações com LLMs
- **OpenAI**: Modelos de linguagem
- **JWT**: Autenticação baseada em tokens
- **Pydantic**: Validação de dados
- **SlowAPI**: Rate limiting
- **Uvicorn**: Servidor ASGI

## 📝 Licença

MIT

## 👤 Autor

Renato Saldanha - ranalisesaldanha@gmail.com
