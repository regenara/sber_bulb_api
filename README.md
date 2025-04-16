# Sber Bulb API

## Описание / Description 
[Эта библиотека](https://pypi.org/project/sber-bulb-api/) предоставляет API-обертку для управления умной лампочкой от Сбера A60. Возможность работы с другими моделями не проверялась. Для использования данной библиотеки необходимо быть зарегистрированным пользователем в приложении Салют!, а также иметь лампочку, добавленную в это приложение.

[This library](https://pypi.org/project/sber-bulb-api/) provides an API wrapper for controlling the Sber A60 smart bulb. Compatibility with other models has not been tested. To use this library, you must be a registered user of the Salute! app and have the bulb added to your account.

## Установка / Installation
```bash
pip install sber-bulb-api
```

## Авторизация / Authorization

### Авторизация через код / Authorization via code
Этот метод предназначен только для первичной авторизации. Чрезмерное использование может привести к блокировке или ограничению сервером. Получите refresh token и используйте метод авторизации через него.

This method is only intended for initial authorization. Excessive use may result in server blocking or restrictions. Obtain a refresh token and use the refresh token authorization method instead.

```python
import asyncio

from sber_smart_bulb_api import SberSmartBulbAPI

PHONE = '79998887766'

async def auth():
    sber_api = SberSmartBulbAPI()
    response = await sber_api.authenticate(phone=PHONE)
    await asyncio.sleep(1)
    sms = input('SMS: ').strip()
    response = await sber_api.verify(ouid=response.ouid, sms_otp=sms)
    await sber_api.get_access_token(authcode=response.authcode)
    print(sber_api.refresh_token)  # Save refresh token
```

### Авторизация через refresh token / Authorization via refresh token
**Внимание:** Refresh token одноразовый!

**Warning:** The refresh token is single-use!

```python
from sber_smart_bulb_api import SberSmartBulbAPI

refresh_token = 'your_refresh_token'

async def main():
    sber_api = SberSmartBulbAPI(refresh_token=refresh_token)
    await sber_api.get_device_groups()
    print(sber_api.refresh_token)  # Save new refresh token
```

## Использование / Usage
```python
import asyncio

from sber_smart_bulb_api import SberSmartBulbAPI
from sber_smart_bulb_api.models import DeviceSceneEnum

refresh_token = 'your_refresh_token'

async def main():
    sber_api = SberSmartBulbAPI(refresh_token=refresh_token)
    groups = await sber_api.get_device_groups()
    print(sber_api.refresh_token)  # Save new refresh token
    group_id = groups.result[0].id
    devices = await sber_api.get_device_group_tree(group_id=group_id)
    device_id = [d.id for d in devices.devices if d.device_info.model == 'smart bulb a60'][0]
    device = await sber_api.get_device(device_id=device_id)
    states = await sber_api.get_device_states(device_id=device_id)
    print(
        f'Device: {device}',
        f'Status (on/off): {states.on_off}',
        f'Work Mode: {states.work_mode}',
        f'Online status: {states.online}',
        f'Scene: {states.light_scene}',
        f'White bright: {states.bright_value_v2}',
        f'White temp: {states.temp_value_v2}',
        f'Colour data: {states.colour_data_v2}',
        f'Sleep timer (minutes): {states.sleep_timer}',
        sep='\n'
    )
    await sber_api.set_on_off(device_id=device_id, value=True)
    await sber_api.set_white(device_id=device_id, brightness=50, temp=50)
    await asyncio.sleep(3)
    await sber_api.set_color(device_id=device_id, h=180, s=50, v=50)
    await asyncio.sleep(3)
    await sber_api.set_scene(device_id=device_id, scene=DeviceSceneEnum.candle)
    await asyncio.sleep(3)
    await sber_api.set_timer(device_id=device_id, minutes=30)
    await sber_api.set_on_off(device_id=device_id, value=False)
    await sber_api.close()

if __name__ == '__main__':
    asyncio.run(main())
```

