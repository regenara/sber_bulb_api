class SberSmartBulbAPIError(Exception):
    """"""


class AuthorizationRequiredSberSmartBulbAPIError(SberSmartBulbAPIError):
    def __init__(self):
        super().__init__("\n-----------------------------------------------------------------\n"
                         "sber_api = SberSmartBulbAPI()\n"
                         "response = await sber_api.authenticate(phone=PHONE)\n"
                         "await asyncio.sleep(1)\n"
                         "sms = input('SMS: ').strip()\n"
                         "response = await sber_api.verify(ouid=response.ouid, sms_otp=sms)\n"
                         "await sber_api.get_access_token(authcode=response.authcode)\n"
                         "print(sber_api.refresh_token)  # Save refresh token"
                         "\n\nOR\n\n"
                         "sber_api = SberSmartBulbAPI(refresh_token=refresh_token)"
                         "\n-----------------------------------------------------------------\n")


class TimeoutSberSmartBulbAPIError(SberSmartBulbAPIError):
    """"""


class ClientConnectorSberSmartBulbAPIError(SberSmartBulbAPIError):
    """"""


class UnknownSberSmartBulbAPIError(SberSmartBulbAPIError):
    """"""
