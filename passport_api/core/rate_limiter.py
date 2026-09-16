from slowapi import Limiter
from slowapi.util import get_remote_address

# Límite por IP de cliente: mitiga fuerza bruta sobre /login y /register
limiter = Limiter(key_func=get_remote_address)