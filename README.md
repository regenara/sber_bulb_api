# Rubetek Socket API

### Описание / Description 
Эта библиотека предоставляет API-обертку для управления умной розеткой Rubetek RE-3305. Возможность работы с другими моделями не проверялась, но, вероятно, поддерживается. Для использования данной библиотеки необходимо быть зарегистрированным пользователем в приложении Rubetek, а также иметь устройство, добавленное в ваше приложение.

<br>This library provides an API wrapper for controlling the Rubetek RE-3305 smart socket. While compatibility with other models has not been tested, it is likely supported. To use this library, you must be a registered user in the Rubetek app and have your device added to the app.


## Установка / Installation
```bash
pip install rubetek-socket-api
```

## Авторизация / Authorization
### Авторизация через код / Authorization via code
Этот метод предназначен только для первичной авторизации. Чрезмерное использование может привести к блокировке или ограничению сервером. Получите refresh token и используйте его для будущих запросов.

<br>This method is intended only for initial authorization. Frequent use may result in server-side blocking or rate limitations. Obtain a refresh token and use it for future requests.
```python
import asyncio

from rubetek_socket_api import RubetekSocketAPI

PHONE = 'your_phone'
EMAIL = 'your_email'

async def sms_auth():
    rubetek_api = RubetekSocketAPI()
    await rubetek_api.send_code(phone=PHONE)
    code = input('Enter the code: ')
    await rubetek_api.change_code_to_access_token(code=code, phone=PHONE)
    print(f'Refresh Token: {rubetek_api.refresh_token}')  # Save refresh token
    user_info = await rubetek_api.get_user()
    print(user_info)

# OR
    
async def email_auth():
    rubetek_api = RubetekSocketAPI()
    await rubetek_api.send_code(email=EMAIL)
    code = input('Enter the code: ')
    await rubetek_api.change_code_to_access_token(code=code, email=EMAIL)
    print(f'Refresh Token: {rubetek_api.refresh_token}')  # Save refresh token
    user_info = await rubetek_api.get_user()
    print(user_info)
```
### Авторизация через refresh token / Authorization via refresh token
```python
import asyncio

from rubetek_socket_api import RubetekSocketAPI

REFRESH_TOKEN = 'your_refresh_token'

async def main():
    rubetek_api = RubetekSocketAPI(refresh_token=REFRESH_TOKEN)
    user_info = await rubetek_api.get_user()
    print(user_info)
```

## Использование / Usage
```python
import asyncio

from rubetek_socket_api import RubetekSocketAPI

REFRESH_TOKEN = 'your_refresh_token'

async def main():
    rubetek_api = RubetekSocketAPI(refresh_token=REFRESH_TOKEN)
    houses = await rubetek_api.get_houses()
    house_id = houses[0].id
    devices = await rubetek_api.get_house_devices(house_id=house_id)
    device_id = devices[0].id
    device = await rubetek_api.get_device(house_id=house_id, device_id=device_id)
    
    print(
        f'Status (on/off): {device.state.relay_on}',
        f'RGB level: {device.state.rgb_level}',
        f'Online status: {device.online}',
        f'Sleep timer (minutes): {device.state.relay_mode}',
        sep='\n'
    )
    
    await rubetek_api.set_rgb_level(house_id=house_id, device_id=device_id, value=100)
    await rubetek_api.set_on_off(house_id=house_id, device_id=device_id, value=not device.state.relay_on)
    await rubetek_api.set_disable_timer(house_id=house_id, device_id=device_id, value=60)

    await rubetek_api.close()

asyncio.run(main())
```

