# Rate limiting for Phishing Classifier API
#
# Uses slowapi (wraps limits/ratelimit) which integrates cleanly with FastAPI.
#
# Installation:
#   pip install slowapi
#
# Usage — add these lines to main.py:
#
#   from rate_limit import limiter, rate_limit_handler
#   from slowapi.errors import RateLimitExceeded
#
#   app.state.limiter = limiter
#   app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
#
# Then decorate any route:
#
#   @app.post("/check")
#   @limiter.limit("30/minute")
#   async def check_url(request: Request, ...):
#       ...
#
# The Request object must be the first parameter of the route function.

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Key function — rate-limit per caller IP address.
# If you add auth, swap get_remote_address for a function that returns the API key instead.
limiter = Limiter(key_func=get_remote_address, default_limits=["200/day", "60/hour"])

# Re-export the built-in handler so main.py can register it in one line
rate_limit_handler = _rate_limit_exceeded_handler
