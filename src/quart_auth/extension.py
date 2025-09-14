import time
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import auto, Enum
from hashlib import sha512
from typing import Any, AsyncGenerator, cast, Dict, Iterable, Literal, Optional, Type, Union

try:
    import orjson
    HAS_ORJSON = True
except ImportError:
    import json
    HAS_ORJSON = False

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from quart import (
    current_app,
    has_request_context,
    has_websocket_context,
    Quart,
    request,
    Response,
    websocket,
)
from quart.globals import request_ctx, websocket_ctx
from quart.typing import TestClientProtocol
from werkzeug.exceptions import Unauthorized as WerkzeugUnauthorized

DEFAULTS = {
    "QUART_AUTH_ATTRIBUTE_NAME": "_quart_auth_user",
    "QUART_AUTH_AUTO_RENEW_ON_MODIFICATION": True,
    "QUART_AUTH_BASIC_USERNAME": None,
    "QUART_AUTH_BASIC_PASSWORD": None,
    "QUART_AUTH_COOKIE_DOMAIN": None,
    "QUART_AUTH_COOKIE_NAME": "QUART_AUTH",
    "QUART_AUTH_COOKIE_PATH": "/",
    "QUART_AUTH_COOKIE_HTTP_ONLY": True,
    "QUART_AUTH_COOKIE_SAMESITE": "Lax",
    "QUART_AUTH_COOKIE_SECURE": True,
    "QUART_AUTH_DURATION": 365 * 24 * 60 * 60,  # 1 Year (for remember_me sessions)
    "QUART_AUTH_SESSION_DURATION": 24 * 60 * 60,  # 24 hours (for regular sessions)
    "QUART_AUTH_MODE": "cookie",  # "bearer" | "cookie"
    "QUART_AUTH_SALT": "quart auth salt",
}


class Unauthorized(WerkzeugUnauthorized):
    pass


class UserDataModificationError(RuntimeError):
    """Raised when trying to modify user data for an unauthenticated user."""
    pass


class Action(Enum):
    DELETE = auto()
    PASS = auto()
    WRITE = auto()
    WRITE_PERMANENT = auto()


class _AuthSerializer(URLSafeTimedSerializer):
    def __init__(
        self, secret: Union[str, bytes, Iterable[str], Iterable[bytes]], salt: Union[str, bytes]
    ) -> None:
        super().__init__(secret, salt, signer_kwargs={"digest_method": sha512})

    def dumps(self, obj: Any, **kwargs) -> str:
        """Override dumps to use orjson for dict serialization if available."""
        if isinstance(obj, dict) and HAS_ORJSON:
            # Use orjson for better performance with dictionaries
            json_bytes = orjson.dumps(obj, option=orjson.OPT_SORT_KEYS)
            json_str = json_bytes.decode('utf-8')
            return super().dumps(json_str, **kwargs)
        else:
            # Use default itsdangerous serialization
            return super().dumps(obj, **kwargs)

    def loads(self, s: str, **kwargs) -> Any:
        """Override loads to use orjson for dict deserialization if available."""
        payload = super().loads(s, **kwargs)

        # If payload is a JSON string (indicating it was serialized with orjson)
        # and we have orjson available, deserialize it
        if isinstance(payload, str) and HAS_ORJSON:
            try:
                # Try to parse as JSON - if it succeeds, it was a dict
                return orjson.loads(payload.encode('utf-8'))
            except (orjson.JSONDecodeError, ValueError):
                # If it fails, it was just a regular string
                return payload
        else:
            return payload


class AuthUser(dict):
    """A base class for users that behaves like a mutable dictionary.

    Any specific user implementation used with Quart-Auth should
    inherit from this. The user data is stored separately from auth_id,
    and modifications automatically trigger cookie updates.
    """

    def __init__(self, auth_id: Optional[str], action: Action = Action.PASS, remember_me: bool = False, expires_at: Optional[int] = None, **user_data) -> None:
        super().__init__(user_data)
        self._auth_id = auth_id
        self.action = action
        self._user_data = user_data
        self._remember_me = remember_me
        self._expires_at = expires_at

        # Warn if expires_at is manually set (likely incorrect usage)
        if expires_at is not None:
            import inspect
            frame = inspect.currentframe()
            try:
                # Check if called directly by user code (not from quart-auth internals)
                caller_filename = frame.f_back.f_code.co_filename if frame.f_back else ""
                if "quart_auth" not in caller_filename:
                    warnings.warn(
                        "Manually setting expires_at is not recommended. "
                        "Use create_user_with_data() instead of AuthUser() directly.",
                        UserWarning,
                        stacklevel=2
                    )
            finally:
                del frame

    @property
    def auth_id(self) -> Optional[str]:
        return self._auth_id

    @property
    def remember_me(self) -> bool:
        """Check if this user session should be remembered (permanent cookie)."""
        return self._remember_me

    @property
    def expires_at(self) -> Optional[datetime]:
        """Get the expiration datetime of the session."""
        if self._expires_at is None:
            return None
        return datetime.fromtimestamp(self._expires_at)

    @property
    def remaining(self) -> Optional[timedelta]:
        """Get the remaining time before session expires."""
        if self._expires_at is None:
            return None
        expires = datetime.fromtimestamp(self._expires_at)
        remaining = expires - datetime.now()
        return remaining if remaining.total_seconds() > 0 else timedelta(0)

    @property
    def user_data(self) -> Dict[str, Any]:
        """Get a copy of the user data."""
        return self._user_data.copy()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a specific piece of user data."""
        return self._user_data.get(key, default)

    def _trigger_update(self) -> None:
        """Trigger cookie update while preserving WRITE_PERMANENT based on remember_me."""
        # Check if user is authenticated before allowing modifications
        if self._auth_id is None:
            raise UserDataModificationError(
                "Cannot modify user data: user is not authenticated. "
                "Please log in first or use @login_required decorator."
            )

        # Use remember_me property to determine if should be permanent
        if self._remember_me:
            self.action = Action.WRITE_PERMANENT

            # Auto-renewal pour sessions permanentes selon config
            try:
                auth_instance = None
                for ext in current_app.extensions.get("QUART_AUTH", []):
                    if hasattr(ext, 'auto_renew_on_modification'):
                        auth_instance = ext
                        break

                if auth_instance and auth_instance.auto_renew_on_modification:
                    # Reset expiration lors de modification si auto_renew activé
                    self._expires_at = int(time.time()) + auth_instance.duration
            except (RuntimeError, AttributeError):
                # Si pas de contexte app ou config non trouvée, on garde l'expiration existante
                pass
        else:
            self.action = Action.WRITE

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        self._user_data[key] = value
        # Trigger cookie update while preserving permanence
        self._trigger_update()

    def __delitem__(self, key: str) -> None:
        super().__delitem__(key)
        if key in self._user_data:
            del self._user_data[key]
        # Trigger cookie update while preserving permanence
        self._trigger_update()

    def update(self, *args, **kwargs) -> None:
        super().update(*args, **kwargs)
        self._user_data.update(*args, **kwargs)
        # Trigger cookie update while preserving permanence
        self._trigger_update()

    def pop(self, key: str, default: Any = None) -> Any:
        result = super().pop(key, default)
        self._user_data.pop(key, default)
        # Trigger cookie update while preserving permanence
        self._trigger_update()
        return result

    def clear(self) -> None:
        super().clear()
        self._user_data.clear()
        # Trigger cookie update while preserving permanence
        self._trigger_update()

    @property
    async def is_authenticated(self) -> bool:
        return self._auth_id is not None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(auth_id={self._auth_id}, action={self.action}, data={dict(self)})"


class QuartAuth:
    user_class = AuthUser
    serializer_class = _AuthSerializer

    def __init__(
        self,
        app: Optional[Quart] = None,
        *,
        attribute_name: str = None,
        auto_renew_on_modification: Optional[bool] = None,
        cookie_domain: Optional[str] = None,
        cookie_name: Optional[str] = None,
        cookie_path: Optional[str] = None,
        cookie_http_only: Optional[bool] = None,
        cookie_samesite: Optional[Literal["Strict", "Lax"]] = None,
        cookie_secure: Optional[bool] = None,
        duration: Optional[int] = None,
        session_duration: Optional[int] = None,
        mode: Optional[Literal["cookie", "bearer"]] = None,
        salt: Optional[str] = None,
        singleton: bool = True,
        serializer_class: Optional[Type[_AuthSerializer]] = None,
        user_class: Optional[Type[AuthUser]] = None,
    ) -> None:
        self.attribute_name = attribute_name
        self.auto_renew_on_modification = auto_renew_on_modification
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_http_only = cookie_http_only
        self.cookie_samesite = cookie_samesite
        self.cookie_secure = cookie_secure
        self.duration = duration
        self.session_duration = session_duration
        self.mode = mode
        self.salt = salt
        self.singleton = singleton
        if serializer_class is not None:
            self.serializer_class = serializer_class
        if user_class is not None:
            self.user_class = user_class
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Quart) -> None:
        if self.attribute_name is None:
            self.attribute_name = _get_config_or_default("QUART_AUTH_ATTRIBUTE_NAME", app)
        if self.auto_renew_on_modification is None:
            self.auto_renew_on_modification = _get_config_or_default("QUART_AUTH_AUTO_RENEW_ON_MODIFICATION", app)
        if self.cookie_domain is None:
            self.cookie_domain = _get_config_or_default("QUART_AUTH_COOKIE_DOMAIN", app)
        if self.cookie_name is None:
            self.cookie_name = _get_config_or_default("QUART_AUTH_COOKIE_NAME", app)
        if self.cookie_path is None:
            self.cookie_path = _get_config_or_default("QUART_AUTH_COOKIE_PATH", app)
        if self.cookie_http_only is None:
            self.cookie_http_only = _get_config_or_default("QUART_AUTH_COOKIE_HTTP_ONLY", app)
        if self.cookie_samesite is None:
            self.cookie_samesite = _get_config_or_default("QUART_AUTH_COOKIE_SAMESITE", app)
        if self.cookie_secure is None:
            self.cookie_secure = _get_config_or_default("QUART_AUTH_COOKIE_SECURE", app)
        if self.duration is None:
            self.duration = _get_config_or_default("QUART_AUTH_DURATION", app)
        if self.session_duration is None:
            self.session_duration = _get_config_or_default("QUART_AUTH_SESSION_DURATION", app)
        if self.mode is None:
            self.mode = _get_config_or_default("QUART_AUTH_MODE", app)
        if self.salt is None:
            self.salt = _get_config_or_default("QUART_AUTH_SALT", app)

        if any(
            ext.attribute_name == self.attribute_name
            or ext.cookie_name == self.cookie_name
            or ext.salt == self.salt
            for ext in app.extensions.get("QUART_AUTH", [])
        ):
            warnings.warn(
                "The same attribute name/cookie name/salt is used by another QuartAuth "
                "instance, this may result in insecure usage."
            )

        app.extensions.setdefault("QUART_AUTH", []).append(self)

        if sum(ext.singleton for ext in app.extensions["QUART_AUTH"]) > 2:
            raise RuntimeError(
                "Multiple singleton extensions, please see docs about multiple auth users"
            )

        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.after_websocket(self.after_websocket)  # type: ignore
        if self.singleton:
            app.context_processor(self._template_context)

    def resolve_user(self) -> AuthUser:
        if self.mode == "cookie":
            token_data = self.load_cookie()
        else:
            token_data = self.load_bearer()

        if isinstance(token_data, dict):
            auth_id = token_data.get('auth_id')
            remember_me = token_data.get('remember_me', False)
            expires_at = token_data.get('expires_at')
            user_data = {k: v for k, v in token_data.items() if k not in ('auth_id', 'remember_me', 'expires_at')}

            # Verify server-side expiration
            if expires_at is not None:
                current_time = int(time.time())
                if current_time > expires_at:
                    # Session has expired server-side, return unauthenticated user
                    return self.user_class(None)

            # Create user with appropriate action and system data
            action = Action.WRITE_PERMANENT if remember_me else Action.PASS
            user = self.user_class(auth_id, action=action, remember_me=remember_me, expires_at=expires_at, **user_data)

            # Auto-renewal for regular sessions (remember_me=False)
            # Sessions normales se renouvellent à chaque visite
            if not remember_me and expires_at is not None:
                # Reset expiration pour sessions normales à chaque requête
                current_time = int(time.time())
                new_expires_at = current_time + self.session_duration
                user._expires_at = new_expires_at
                user.action = Action.WRITE  # Trigger cookie update

            return user
        else:
            # Backward compatibility: if token_data is just a string (old format)
            return self.user_class(token_data)

    async def before_request(self) -> Optional[Response]:
        """Check if session has expired server-side and mark for deletion."""
        if self.mode != "cookie":
            return None

        # Pre-load user to trigger expiration check
        user = self.load_user()

        # If user was supposed to be authenticated but session expired server-side
        # we need to delete the cookie
        if hasattr(request, 'cookies') and self.cookie_name in request.cookies:
            token_data = self.load_cookie()
            if isinstance(token_data, dict) and token_data.get('expires_at'):
                current_time = int(time.time())
                if current_time > token_data.get('expires_at'):
                    # Session expired - mark user for cookie deletion
                    user.action = Action.DELETE
                    setattr(request_ctx, self.attribute_name, user)

        return None

    def load_cookie(self) -> Union[Optional[str], Optional[Dict[str, Any]]]:
        try:
            token = ""
            if has_request_context():
                token = request.cookies[self.cookie_name]
            elif has_websocket_context():
                token = websocket.cookies[self.cookie_name]
        except KeyError:
            return None
        else:
            return self.load_token(token)

    def load_bearer(self) -> Union[Optional[str], Optional[Dict[str, Any]]]:
        try:
            if has_request_context():
                raw = request.headers["Authorization"]
            elif has_websocket_context():
                raw = websocket.headers["Authorization"]
        except KeyError:
            return None
        else:
            if raw[:6].lower() != "bearer":
                return None
            token = raw[6:].strip()
            return self.load_token(token)

    def dump_token(self, data: Union[str, Dict[str, Any]], app: Optional[Quart] = None) -> str:
        if app is None:
            app = current_app

        serializer = self.serializer_class(app.secret_key, self.salt)

        # Handle both string (old format) and dict (new format)
        if isinstance(data, str):
            # Backward compatibility: if data is just a string, treat it as auth_id
            payload = data
        else:
            # New format: serialize the entire dictionary
            payload = data

        return serializer.dumps(payload)

    def load_token(self, token: str, app: Optional[Quart] = None) -> Union[Optional[str], Optional[Dict[str, Any]]]:
        if app is None:
            app = current_app

        keys = []

        if fallbacks := app.config.get("SECRET_KEY_FALLBACKS"):
            keys.extend(fallbacks)

        keys.append(app.secret_key)  # itsdangerous expects current key at top

        serializer = self.serializer_class(keys, self.salt)  # type: ignore[arg-type]
        try:
            payload = serializer.loads(token, max_age=self.duration)
            return payload  # Can be either string or dict
        except (BadSignature, SignatureExpired):
            return None

    async def after_request(self, response: Response) -> Response:
        user = self.load_user()
        if self.mode == "bearer":
            if user.action != Action.PASS:
                warnings.warn("Login/logout/renew have no affect in bearer mode")

            return response

        if user.action == Action.DELETE:
            response.delete_cookie(
                self.cookie_name,
                domain=self.cookie_domain,
                httponly=cast(bool, self.cookie_http_only),
                path=self.cookie_path,
                secure=cast(bool, self.cookie_secure),
                samesite=self.cookie_samesite,
            )
        elif user.action in {Action.WRITE, Action.WRITE_PERMANENT}:
            max_age = None
            remember_me = user.action == Action.WRITE_PERMANENT

            if remember_me:
                # Sessions permanentes (remember_me=True)
                max_age = self.duration  # Cookie expire dans 1 an
            else:
                # Sessions normales (remember_me=False)
                max_age = None  # Pas d'expiration cookie = session browser

            if self.cookie_secure and not request.is_secure:
                warnings.warn("Secure cookies will be ignored on insecure requests")

            if self.cookie_samesite == "Strict" and 300 <= response.status_code < 400:
                warnings.warn("Strict samesite cookies will be ignored on redirects")

            # Create token data with auth_id, remember_me, expires_at, and user_data
            if user._user_data or remember_me or user.auth_id:
                # Always add expiration timestamp for security
                token_data = {'auth_id': user.auth_id, 'remember_me': remember_me, **user._user_data}

                # Utiliser l'expiration déjà définie sur l'utilisateur
                if user._expires_at:
                    token_data['expires_at'] = user._expires_at
                elif remember_me:
                    # Fallback pour sessions permanentes
                    token_data['expires_at'] = int(time.time()) + self.duration
                else:
                    # Fallback pour sessions normales
                    token_data['expires_at'] = int(time.time()) + self.session_duration

                token = self.dump_token(token_data)
            else:
                # Backward compatibility: if no user_data and not permanent, just use auth_id
                token = self.dump_token(user.auth_id)
            response.set_cookie(
                self.cookie_name,
                token,
                domain=self.cookie_domain,
                max_age=max_age,
                httponly=cast(bool, self.cookie_http_only),
                path=self.cookie_path,
                secure=cast(bool, self.cookie_secure),
                samesite=self.cookie_samesite,
            )
        return response

    async def after_websocket(self, response: Optional[Response]) -> Optional[Response]:
        user = self.load_user()
        if self.mode == "bearer":
            if user.action != Action.PASS:
                warnings.warn("Login/logout/renew have no affect in bearer mode")

            return response

        if user.action != Action.PASS:
            if response is not None:
                warnings.warn(
                    "The auth cookie may not be set by the client. "
                    "Cookies are unreliably set on websocket responses."
                )
            else:
                warnings.warn("The auth cookie cannot be set by the client.")

        return response

    def load_user(self) -> AuthUser:
        if has_request_context():
            if not hasattr(request_ctx, self.attribute_name):
                user = self.resolve_user()
                setattr(request_ctx, self.attribute_name, user)

            return getattr(
                request_ctx,
                self.attribute_name,
                self.user_class(None),
            )
        elif has_websocket_context():
            if not hasattr(websocket_ctx, self.attribute_name):
                user = self.resolve_user()
                setattr(websocket_ctx, self.attribute_name, user)

            return getattr(
                websocket_ctx,
                self.attribute_name,
                self.user_class(None),
            )
        else:
            return self.user_class(None)

    def login_user(self, user: AuthUser) -> None:
        if has_request_context():
            # Ensure user has expiration timestamp if not already set
            if user._expires_at is None:
                if user._remember_me:
                    # Session permanente : utilise duration (ex: 1 an)
                    user._expires_at = int(time.time()) + self.duration
                else:
                    # Session normale : utilise session_duration (ex: 24h)
                    user._expires_at = int(time.time()) + self.session_duration

            setattr(request_ctx, self.attribute_name, user)
        else:
            raise RuntimeError("Cannot login unless within a request context")

    def logout_user(self) -> None:
        user = self.user_class(None)
        user.action = Action.DELETE
        if has_request_context():
            setattr(request_ctx, self.attribute_name, user)
        else:
            raise RuntimeError("Cannot logout unless within a request context")

    @asynccontextmanager
    async def authenticated_client(
        self, client: TestClientProtocol, auth_id: str
    ) -> AsyncGenerator[None, None]:
        if client.cookie_jar is None or self.mode != "cookie":
            raise RuntimeError("Authenticated transactions only make sense with cookies enabled.")

        token = self.dump_token(auth_id, app=client.app)
        client.set_cookie(
            self.cookie_domain,
            self.cookie_name,
            token,
            path=self.cookie_path,
            domain=self.cookie_domain,
            secure=cast(bool, self.cookie_secure),
            httponly=cast(bool, self.cookie_http_only),
            samesite=self.cookie_samesite,
        )
        yield
        client.delete_cookie(
            self.cookie_domain,
            self.cookie_name,
            path=self.cookie_path,
            domain=self.cookie_domain,
        )

    def _template_context(self) -> Dict[str, AuthUser]:
        return {"current_user": self.load_user()}


def _get_config_or_default(config_key: str, app: Quart) -> Any:
    return app.config.get(config_key, DEFAULTS[config_key])
