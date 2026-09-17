import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from openai import OpenAI
from pydantic import BaseModel, Field

from auth.dependencies import CurrentUser
from auth.providers import ProviderVerifier
from auth.routes import profile_router
from auth.routes import router as auth_router
from auth.service import AuthService
from config import Settings, cors_origins_from_env
from database import Database


def get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(503, "Text generation is not configured")
    return OpenAI(api_key=api_key)


class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=32000)


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        configured = settings if settings is not None else Settings.from_env()
        database = Database(configured.database_path)
        database.initialize()
        app.state.auth_service = AuthService(configured, database, ProviderVerifier(configured))
        yield

    app = FastAPI(title="ProteinMaxxer API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins if settings else cors_origins_from_env(),
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(auth_router)
    app.include_router(profile_router)

    @app.middleware("http")
    async def private_responses(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(("/auth/", "/profile")):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Do not echo passwords or provider tokens in validation responses.
        errors = [
            {"type": error["type"], "loc": error["loc"], "msg": error["msg"]}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.get("/health", tags=["Health"])
    def health():
        return {"status": "ok"}

    @app.post("/generate", tags=["Generation"])
    def generate_text(req: PromptRequest, user: CurrentUser):
        with get_openai_client() as client:
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[{"role": "user", "content": req.prompt}],
            )
        return {"output": response.choices[0].message.content}

    @app.post("/stream", tags=["Generation"])
    def stream_response(req: PromptRequest, user: CurrentUser):
        client = get_openai_client()

        def event_stream():
            with client:
                with client.chat.completions.create(
                    model="gpt-4.1-mini",
                    messages=[{"role": "user", "content": req.prompt}],
                    stream=True,
                ) as stream:
                    for chunk in stream:
                        if chunk.choices and chunk.choices[0].delta.content:
                            yield chunk.choices[0].delta.content

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app


app = create_app()
