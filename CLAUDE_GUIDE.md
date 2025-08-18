# Claude Code Guide: Using cjm-fasthtml-byok Library

## Overview

The `cjm-fasthtml-byok` library provides secure API key management for FastHTML applications with encrypted storage, session/database persistence, and built-in UI components. This guide helps Claude Code properly integrate and use this library when developing FastHTML applications.

## Quick Start

### Installation

```bash
pip install cjm_fasthtml_byok
```

### Minimal Setup (Session Storage Only)

```python
from fasthtml.common import *
from cjm_fasthtml_byok.core.storage import BYOKManager
from cjm_fasthtml_byok.middleware.beforeware import create_byok_beforeware
from starlette.middleware.sessions import SessionMiddleware

# Initialize BYOK
SECRET_KEY = "your-secret-key-change-in-production"
byok = BYOKManager(secret_key=SECRET_KEY)

# Create app with session support and beforeware
app, rt = fast_app(
    secret_key=SECRET_KEY,
    sess_cls=SessionMiddleware,
    before=create_byok_beforeware(byok)
)
```

## Core Components

### 1. BYOKManager - The Main Manager

```python
from cjm_fasthtml_byok.core.storage import BYOKManager
from cjm_fasthtml_byok.core.types import BYOKConfig, StorageBackend
from datetime import timedelta

# Basic setup (session storage)
byok = BYOKManager(secret_key="your-secret")

# With database (hybrid storage)
byok = BYOKManager(
    secret_key="your-secret",
    db_url="sqlite:///keys.db"  # Or PostgreSQL: "postgresql://user:pass@host/db"
)

# With custom configuration
config = BYOKConfig(
    storage_backend=StorageBackend.HYBRID,  # SESSION, DATABASE, or HYBRID
    default_ttl=timedelta(hours=24),
    auto_cleanup=True,
    require_https=True  # Set False for development
)
byok = BYOKManager(secret_key="your-secret", db_url="...", config=config)
```

### 2. Storage Backends

- **SESSION**: Keys stored in user session (temporary, per-session)
- **DATABASE**: Keys stored in database (persistent, cross-session)
- **HYBRID**: Both session (cache) and database (persistence)

### 3. Key Operations

```python
# Store a key
byok.set_key(
    request,
    provider="openai",  # ANY provider name works
    api_key="sk-...",
    user_id="550e8400-e29b-41d4-a716-446655440000",  # User's UUID from your auth system
    ttl=timedelta(days=30)  # Optional expiration
)

# Retrieve a key (using same UUID)
api_key = byok.get_key(request, "openai", user_id="550e8400-e29b-41d4-a716-446655440000")

# Check if key exists
has_key = byok.has_key(request, "openai", user_id="550e8400-e29b-41d4-a716-446655440000")

# Delete a key
byok.delete_key(request, "openai", user_id="550e8400-e29b-41d4-a716-446655440000")

# List all providers with keys
providers = byok.list_providers(request, user_id="550e8400-e29b-41d4-a716-446655440000")

# Clear all keys
byok.clear_keys(request, user_id="550e8400-e29b-41d4-a716-446655440000")

# In practice, you'd use a helper function:
user_id = get_user_id(request)  # Returns the UUID from session
api_key = byok.get_key(request, "openai", user_id=user_id)
```

## UI Components

### Forms

```python
from cjm_fasthtml_byok.components.forms import (
    KeyInputForm,
    MultiProviderKeyForm,
    KeyManagementCard,
    KeyManagerDashboard,
    InlineKeyInput
)

# Single provider form (works with ANY provider name)
form = KeyInputForm(
    provider="my_service",  # Any name works!
    action="/api/keys/my_service",
    show_help=True
)

# Multi-provider selector
form = MultiProviderKeyForm(
    providers=["openai", "anthropic", "my_custom_api"],
    action="/api/keys",
    default_provider="openai"
)

# Management card for a provider
card = KeyManagementCard(
    provider="my_api",
    has_key=True,
    masked_key="key-...xyz",
    created_at="2 hours ago",
    delete_action="/api/keys/my_api/delete",
    update_action="/api/keys/my_api"
)

# Complete dashboard (best for settings page)
dashboard = KeyManagerDashboard(
    request,
    providers=["service_a", "service_b", "service_c"],
    byok_manager=byok,
    user_id="user123",
    base_url="/api/keys"
)

# Inline input (compact)
inline = InlineKeyInput(
    provider="my_service",
    on_save="/api/keys/my_service/quick-save"
)
```

### Alerts & Notifications

```python
from cjm_fasthtml_byok.components.alerts import (
    Alert,
    SecurityAlert,
    KeyStatusNotification,
    ValidationMessage,
    ToastContainer,
    Toast
)

# Basic alert
Alert("API key saved!", kind="success", dismissible=True)

# Security warning
SecurityAlert(
    "API keys transmitted over HTTP",
    severity="high",
    action_url="/settings/security"
)

# Key status notification
KeyStatusNotification(
    provider="openai",
    status="added",  # added, updated, deleted, expired, invalid
    masked_key="sk-...xyz",
    auto_dismiss=True
)

# Form validation
ValidationMessage("Invalid API key format", is_valid=False)

# Toast notifications
ToastContainer(position="top", align="end")
Toast("Key saved!", kind="success", duration=3000)
```

## Middleware & Protection

### Beforeware Setup

```python
from cjm_fasthtml_byok.middleware.beforeware import (
    create_byok_beforeware,
    require_api_key,
    require_any_api_key,
    setup_byok
)

# Simple beforeware
beforeware = create_byok_beforeware(byok)

# Complete setup helper
beforeware_list, byok = setup_byok(
    secret_key="your-secret",
    db="sqlite:///keys.db",
    user_id_func=lambda req: req.session.get("user_id"),
    enable_security_checks=True,
    enable_cleanup=True
)

# Use in app
app, rt = fast_app(before=beforeware_list)
```

### Protected Routes

```python
# Require specific API key
@rt("/chat")
@require_api_key("openai", user_id_func=get_user_id)
def chat(request):
    # Route only accessible if OpenAI key exists
    byok = request.scope['byok']
    api_key = byok.get_key(request, "openai")
    # Use the API key...

# Require any of multiple keys
@rt("/ai-endpoint")
@require_any_api_key(["openai", "anthropic", "google"])
def ai_endpoint(request):
    # Accessible if ANY of the listed keys exist
    pass
```

## Provider Configuration (Optional)

Providers work automatically without configuration, but you can customize them:

```python
# Optional: Define custom provider settings
PROVIDER_CONFIG = {
    'my_service': {
        'name': 'My Custom Service',  # Display name
        'placeholder': 'Enter your service key',  # Input placeholder
        'key_prefix': 'srv-',  # Expected key prefix
        'docs_url': 'https://docs.example.com'  # Documentation link
    }
}

# Pass to components
form = KeyInputForm(
    provider="my_service",
    provider_config=PROVIDER_CONFIG  # Optional
)

# Without config (auto-generates sensible defaults)
form = KeyInputForm(provider="any_name")
# Generates: name="Any Name", placeholder="Enter your Any Name API key"
```

## Helper Functions

```python
from cjm_fasthtml_byok.utils.helpers import (
    get_provider_info,
    format_provider_name,
    format_key_age,
    format_expiration,
    get_key_summary,
    get_env_key,
    import_from_env
)

# Get provider information
info = get_provider_info("my_service", PROVIDER_CONFIG)

# Format for display
name = format_provider_name("my_service")  # "My Service"

# Get summary of all keys
summary = get_key_summary(byok, request, user_id="user123")

# Import from environment variables
results = import_from_env(
    byok, 
    request,
    providers=["openai", "anthropic"],
    user_id="user123",
    env_prefix="API_KEY_"  # Looks for API_KEY_OPENAI, etc.
)
```

## Security Features

```python
from cjm_fasthtml_byok.core.security import (
    mask_key,
    get_key_fingerprint,
    check_https,
    validate_environment
)

# Mask key for display
masked = mask_key("sk-1234567890abcdef")  # "sk-1...cdef"

# Get fingerprint (for logging without exposing key)
fingerprint = get_key_fingerprint("sk-...")  # SHA256 hash

# Check HTTPS
is_secure = check_https(request)

# Validate environment (warns if not HTTPS in production)
validate_environment(request, require_https=True)
```

## Complete Example Pattern

```python
from fasthtml.common import *
from cjm_fasthtml_byok.core.storage import BYOKManager
from cjm_fasthtml_byok.middleware.beforeware import create_byok_beforeware
from cjm_fasthtml_byok.components.forms import KeyInputForm
from cjm_fasthtml_byok.components.alerts import Alert
from starlette.middleware.sessions import SessionMiddleware

# Setup
SECRET_KEY = "your-secret-key"
byok = BYOKManager(
    secret_key=SECRET_KEY,
    db_url="sqlite:///keys.db"  # Optional: for persistence
)

# Create app
app, rt = fast_app(
    secret_key=SECRET_KEY,
    sess_cls=SessionMiddleware,
    before=create_byok_beforeware(byok)
)

# Helper to get user ID
def get_user_id(req):
    return req.session.get("user_id", "default-user")

# Main page with key management
@rt("/")
def index(req, sess):
    provider = "my_api_service"  # ANY name works
    has_key = byok.has_key(req, provider, get_user_id(req))
    
    return Div(
        Alert(
            f"API key {'configured' if has_key else 'not configured'}",
            kind="success" if has_key else "warning"
        ),
        KeyInputForm(provider=provider, action="/save-key")
    )

# Save key endpoint
@rt("/save-key", methods=["POST"])
def save_key(req, sess, api_key: str):
    byok.set_key(req, "my_api_service", api_key, get_user_id(req))
    return RedirectResponse(url="/", status_code=303)

# Protected route
@rt("/protected")
@require_api_key("my_api_service", user_id_func=get_user_id)
def protected(req):
    # Only accessible with API key
    api_key = byok.get_key(req, "my_api_service", get_user_id(req))
    return Div(f"Using API key: {mask_key(api_key)}")
```

## Best Practices

### 1. Database URLs

```python
# Development
db_url = "sqlite:///dev.db"

# Production
db_url = os.environ.get("DATABASE_URL")  # PostgreSQL/MySQL from environment

# Testing
db_url = "sqlite:///:memory:"  # In-memory for tests
```

### 2. User ID Management

The `user_id` should be a **unique, hard-to-guess identifier** from your application's main user database, typically a UUID or similar opaque ID. This ensures proper key isolation between users.

```python
def get_user_id(request):
    # GOOD: UUID from your users table (after authentication)
    if hasattr(request, 'session'):
        return request.session.get("user_id")  # e.g., "550e8400-e29b-41d4-a716-446655440000"
    
    # GOOD: From auth system
    if hasattr(request, 'user'):
        return request.user.id  # Should be UUID or similar
    
    # OK: For single-user/personal apps only
    return "default-user"

# What NOT to use as user_id:
# ❌ "user1", "123" (predictable/guessable)
# ❌ email addresses (PII exposure)
# ❌ sequential integers (enumerable)

# What TO use:
# ✅ UUID: "550e8400-e29b-41d4-a716-446655440000"
# ✅ Random ID: "usr_2n4F8kL9mPqR3xZ"
```

**Integration with Authentication:**

```python
# Login flow - store UUID in session
@rt("/login", methods=["POST"])
def login(request, email: str, password: str):
    user = authenticate_user(email, password)  # Your auth logic
    if user:
        request.session["user_id"] = user.id  # Store UUID, not email!
        request.session["user_email"] = user.email  # For display only
        return RedirectResponse("/dashboard")

# Then use throughout your app
user_id = get_user_id(request)  # Gets the UUID
byok.set_key(request, provider, api_key, user_id=user_id)
```

### 3. Environment Variables

```python
# Store sensitive keys in environment
import os

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///dev.db")

# Import API keys from environment on startup
if os.environ.get("AUTO_IMPORT_KEYS"):
    import_from_env(byok, request, ["openai", "anthropic"])
```

### 4. Error Handling

```python
from cjm_fasthtml_byok.core.types import (
    KeyNotFoundError,
    EncryptionError,
    StorageError
)

try:
    api_key = byok.get_key(request, "openai")
except KeyNotFoundError:
    # Handle missing key
    return Alert("Please configure your OpenAI key", kind="error")
except EncryptionError:
    # Handle decryption failure
    return Alert("Failed to decrypt key", kind="error")
```

## Common Patterns

### Dashboard Page

```python
@rt("/settings/api-keys")
def api_keys_page(req, sess):
    providers = ["openai", "anthropic", "custom_service"]
    return KeyManagerDashboard(
        req,
        providers=providers,
        byok_manager=byok,
        user_id=get_user_id(req)
    )
```

### API Endpoint for Key Management

```python
@rt("/api/keys/{provider}", methods=["POST"])
def update_key(req, sess, provider: str, api_key: str):
    try:
        byok.set_key(req, provider, api_key, get_user_id(req))
        return {"status": "success", "message": f"{provider} key updated"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@rt("/api/keys/{provider}", methods=["DELETE"])
def delete_key(req, sess, provider: str):
    byok.delete_key(req, provider, get_user_id(req))
    return {"status": "success", "message": f"{provider} key deleted"}
```

### Multi-Provider AI Service

```python
@rt("/ai/complete")
@require_any_api_key(["openai", "anthropic", "cohere"])
def ai_complete(req, prompt: str):
    user_id = get_user_id(req)
    
    # Try providers in order
    for provider in ["openai", "anthropic", "cohere"]:
        if byok.has_key(req, provider, user_id):
            api_key = byok.get_key(req, provider, user_id)
            # Use the first available key
            return call_ai_service(provider, api_key, prompt)
    
    return {"error": "No AI provider configured"}
```

## Important Notes for Claude Code

1. **Provider Names Are Flexible**: ANY string works as a provider name. The library auto-generates sensible defaults if no configuration is provided.

2. **Session Middleware Required**: Always include `SessionMiddleware` when creating the FastHTML app.

3. **Beforeware Order Matters**: Add BYOK beforeware to make `request.scope['byok']` available.

4. **User ID Must Be Secure**: The `user_id` should be a UUID or similar unique, hard-to-guess identifier from your main user database (not email, not "user1", not sequential IDs). This ensures proper isolation between users' API keys.

5. **User ID Strategy**: Determine early whether using session-based auth (store UUID in session after login), auth-based (get from auth system), or single-user approach (use fixed ID like "default").

6. **Database Choice**: Use SQLite for development/prototypes, PostgreSQL/MySQL for production.

7. **Security in Production**: Always set `require_https=True` in production environments.

8. **Key Expiration**: Consider setting appropriate TTLs based on security requirements.

9. **Error Messages**: Provide clear feedback when keys are missing or invalid.

## Quick Reference: Component Selection

- **Need a simple key input?** → `KeyInputForm`
- **Multiple providers?** → `MultiProviderKeyForm`
- **Settings page?** → `KeyManagerDashboard`
- **Inline/compact?** → `InlineKeyInput`
- **Status feedback?** → `Alert` or `KeyStatusNotification`
- **Protected route?** → `@require_api_key` decorator
- **Check for key?** → `byok.has_key()`
- **Get the key?** → `byok.get_key()`