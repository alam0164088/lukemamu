"""
Custom CSRF Middleware to exempt API routes
REST APIs don't need CSRF protection since they use token-based auth
"""
from django.middleware.csrf import CsrfViewMiddleware


class APICSRFExemptionMiddleware(CsrfViewMiddleware):
    """
    Exempt API routes from CSRF protection
    Allows REST APIs with JWT/Bearer tokens to work without CSRF tokens
    """
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Exempt /api/ routes from CSRF check
        if request.path.startswith('/api/'):
            return None
        
        # For non-API routes, use default CSRF protection
        return super().process_view(request, view_func, view_args, view_kwargs)
