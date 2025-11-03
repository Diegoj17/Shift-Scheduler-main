from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseServerError


class EnsureCORSOnExceptionMiddleware(MiddlewareMixin):
    """Asegura que respuestas de error generadas por Django incluyan cabeceras CORS.

    Esto ayuda durante desarrollo y debugging: cuando Django produce una excepción
    y devuelve 500, algunos proxies/hosts pueden no propagar cabeceras CORS y el
    navegador muestra "blocked by CORS" en lugar del error real. Este middleware
    añade Access-Control-Allow-Origin (y algunos headers) cuando es posible.
    """

    def process_exception(self, request, exception):
        # No interferimos con DEBUG True que ya muestra el traceback en HTML
        # pero añadimos headers para que el navegador no oculte el error.
        try:
            origin_header = None
            # Preferir permitir origenes listados; si se permite todo, usar '*'
            if getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False):
                origin_header = '*'
            else:
                allowed = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
                if allowed:
                    # Si la petición trae Origin, y está en la lista, usarla.
                    origin = request.META.get('HTTP_ORIGIN')
                    if origin and origin in allowed:
                        origin_header = origin
                    else:
                        # fallback al primer allowed origin
                        origin_header = allowed[0]

            resp = HttpResponseServerError('Internal Server Error')
            if origin_header:
                resp['Access-Control-Allow-Origin'] = origin_header
                resp['Access-Control-Allow-Credentials'] = 'true'
                resp['Access-Control-Allow-Headers'] = 'Authorization,Content-Type'
                resp['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
            return resp
        except Exception:
            # En caso de fallo en el middleware, no queremos esconder la excepción original
            return None
