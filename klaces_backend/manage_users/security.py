from rest_framework.throttling import AnonRateThrottle


class loginThrottle(AnonRateThrottle):
    scope = 'login'
    rate = '5/minute'