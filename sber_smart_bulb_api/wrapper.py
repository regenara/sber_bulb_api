import asyncio
import base64
import hashlib
import logging
import os
from contextlib import suppress
from datetime import datetime
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import (Any,
                    Dict,
                    List,
                    Optional,
                    Union)
from urllib.parse import urljoin
from uuid import uuid4

import jwt
from aiohttp import (ClientSession,
                     ClientTimeout,
                     TCPConnector)
from aiohttp.client_exceptions import (ClientConnectorError,
                                       ContentTypeError)

from .exceptions import (AuthorizationRequiredSberSmartBulbAPIError,
                         ClientConnectorSberSmartBulbAPIError,
                         TimeoutSberSmartBulbAPIError,
                         UnknownSberSmartBulbAPIError)
from .logger import SafeLogger
from .models import (AccessTokenResponse,
                     AuthenticateResponse,
                     ColorValidation,
                     DeviceGroups,
                     DeviceGroupTree,
                     DeviceSceneEnum,
                     DeviceStates,
                     JWTTokenResponse,
                     SceneValidation,
                     SberSmartBulb,
                     TimerValidation,
                     VerifyResponse,
                     WhiteValidation)


class SberSmartBulbAPI:
    def __init__(self, refresh_token: Optional[str] = None,
                 refresh_token_path: Optional[Path] = Path('./sber_refresh_token'),
                 timeout: int = 30, level: logging = logging.INFO):
        self.refresh_token: Optional[str] = refresh_token
        self.refresh_token_path: Optional[Path] = refresh_token_path
        self._x_auth_jwt: Optional[str] = None
        self._access_token: Optional[str] = None

        self._sber_devices_url = f'https://gateway.iot.sberdevices.ru/gateway/v1/'
        self._sber_uapi_url = 'https://online.sberbank.ru/CSAFront/uapi/v2/'
        self._sber_access_token_url = 'https://online.sberbank.ru:4431/CSAFront/api/service/oidc/v3/token'
        self._sber_x_auth_jwt_url = 'https://companion.devices.sberbank.ru/v13/smarthome/token'

        self._client_id = 'b1f0f0c6-fcb0-4ece-8374-6b614ebe3d42'
        self._code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')
        self._rsa_data = {
            'dom_elements': '',
            'htmlinjection': '',
            'manvsmachinedetection': '',
            'js_events': '',
            'deviceprint': 'version=1.7.3&pm_br=Chrome&pm_brmjv=120&iframed=0&intip=&pm_expt=&pm_fpacn=Mozilla&pm_'
                           'fpan=Netscape&pm_fpasw=&pm_fpco=1&pm_fpjv=0&pm_fpln=lang=ru|syslang=|userlang=&pm_fpol=true'
                           '&pm_fposp=&pm_fpsaw=393&pm_fpsbd=&pm_fpsc=24|393|786|786&pm_fpsdx=&pm_fpsdy=&pm_fpslx='
                           '&pm_fpsly=&pm_fpspd=24&pm_fpsui=&pm_fpsw=&pm_fptz=3&pm_fpua=mozilla/5.0 (linux; android '
                           '10; k) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 mobile safari/537.36|5.0 '
                           '(Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile '
                           'Safari/537.36|Linux armv81&pm_fpup=&pm_inpt=&pm_os=Android&adsblock=0=false|1=false|2=false'
                           '|3=false|4=false&audio=baseLatency=0.003|outputLatency=0|sampleRate=48000|state=suspended'
                           '|maxChannelCount=2|numberOfInputs=1|numberOfOutputs=1|channelCount=2|channelCountMode=max'
                           '|channelInterpretation=speakers|fftSize=2048|frequencyBinCount=1024|minDecibels=-100'
                           '|maxDecibels=-30|smoothingTimeConstant=0.8&pm_fpsfse=true&webgl=ver=webgl2|vendor='
                           'Google Inc. (Qualcomm)|render=ANGLE (Qualcomm, Adreno (TM) 630, OpenGL ES 3.2)'
        }
        self._oidc = {
            'scope': 'openid',
            'response_type': 'code',
            'redirect_uri': 'companionapp://host',
            'state': str(uuid4()),
            'nonce': str(uuid4()),
            'code_challenge_method': 'S256',
            'client_id': self._client_id,
            'code_challenge': self._generate_code_challenge,
            'referer_uri': ''
        }
        self._headers = {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Referer': self._sber_uapi_url,
            'User-Agent': 'Salute+prod%2F24.11.1.15991+%28Android+29%3B+Xiaomi+MIX+2S%29'
        }
        self._logger = SafeLogger('SberSmartBulbAPI')
        self._logger.setLevel(level)

        self.session: ClientSession = ClientSession(connector=TCPConnector(ssl=False),
                                                    timeout=ClientTimeout(total=timeout))

    @property
    def _generate_code_challenge(self) -> str:
        sha256_hash = hashlib.sha256(self._code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(sha256_hash).rstrip(b'=').decode('utf-8')

    async def _send_request(self, url: str = None, method: str = 'GET', json: Dict[str, Any] = None,
                            data: Dict[str, Any] = None, headers: Dict[str, Any] = None) -> Dict[str, Any]:
        headers = headers or {'x-auth-jwt': self._x_auth_jwt}
        request_id = uuid4().hex
        self._logger.info('Request=%s method=%s url=%s json=%s data=%s headers=%s', request_id, method, url,
                          json, data, headers)
        await self._check_tokens(headers=headers)
        try:
            async with self.session.request(method, url, json=json, data=data, headers=headers) as response:
                try:
                    json_response = await response.json()
                except (JSONDecodeError, ContentTypeError) as e:
                    raw_response = await response.text()
                    self._logger.error('Response=%s unsuccessful request status=%s reason=%s raw=%s error=%s',
                                       request_id, response.status, response.reason, raw_response, e)
                    raise UnknownSberSmartBulbAPIError(f'Unknown error: {response.status} {response.reason}')

                if response.status != 200:
                    self._logger.error('Response=%s unsuccessful request status=%s reason=%s json_response=%s',
                                       request_id, response.status, response.reason, json_response)
                    state = json_response.get('state', {})
                    raise UnknownSberSmartBulbAPIError(f'{state.get("title") or "Error"}: '
                                                       f'{state.get("message") or json_response}')
                self._logger.info('Response=%s json_response=%s', request_id, json_response)
                return json_response

        except asyncio.exceptions.TimeoutError:
            self._logger.error('Response=%s TimeoutSberSmartBulbAPIError', request_id)
            raise TimeoutSberSmartBulbAPIError('Timeout error')

        except ClientConnectorError:
            self._logger.error('Response=%s ClientConnectorSberSmartBulbAPIError', request_id)
            raise ClientConnectorSberSmartBulbAPIError('Client connector error')

    @staticmethod
    def _check_token(token: Optional[str]) -> bool:
        try:
            payload = jwt.decode(token, options={'verify_signature': False})
            exp = payload.get('exp')
            invalid_token = exp is not None and exp < datetime.now().timestamp()
        except jwt.DecodeError:
            invalid_token = True
        return invalid_token

    async def _check_tokens(self, headers: Dict[str, Any]):
        if 'x-auth-jwt' in headers and self._check_token(token=self._x_auth_jwt):
            self._logger.warning('JWT token invalid, attempting to refresh')
            await self._set_auth_jwt()
            headers['x-auth-jwt'] = self._x_auth_jwt
        if 'Authorization' in headers and self._check_token(token=self._access_token):
            self._logger.warning('Access token invalid, attempting to refresh')
            await self._refresh_access_token()
            headers['Authorization'] = f'Bearer {self._access_token}'

    def _check_refresh_token(self):
        if not self.refresh_token and self.refresh_token_path:
            with suppress(FileNotFoundError):
                with open(self.refresh_token_path) as f:
                    self.refresh_token = f.read()
        if not self.refresh_token:
            self._logger.error('AuthorizationRequiredSberSmartBulbAPIError')
            raise AuthorizationRequiredSberSmartBulbAPIError

    def _save_refresh_token(self, refresh_token: str):
        if self.refresh_token_path:
            with open(self.refresh_token_path, 'w') as f:
                f.write(refresh_token)
            self._logger.info('New refresh token saved to file %s', self.refresh_token_path)

    async def _get_access_token(self, data: Dict[str, Any]) -> AccessTokenResponse:
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = await self._send_request(url=self._sber_access_token_url, method='POST', data=data, headers=headers)
        result = AccessTokenResponse(**response)
        self._access_token = result.access_token
        self.refresh_token = result.refresh_token
        self._save_refresh_token(refresh_token=result.refresh_token)
        return result

    async def _set_auth_jwt(self):
        headers = {'Authorization': f'Bearer {self._access_token}'}
        response = await self._send_request(url=self._sber_x_auth_jwt_url, headers=headers)
        self._x_auth_jwt = JWTTokenResponse(**response).token

    async def _refresh_access_token(self) -> AccessTokenResponse:
        self._check_refresh_token()
        data = {
            'client_id': self._client_id,
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token
        }
        return await self._get_access_token(data=data)

    async def _set_states(self, device_id: str, states: List[Dict[str, Any]]):
        url = urljoin(self._sber_devices_url, f'devices/{device_id}/state')
        json = {'desired_state': states, 'device_id': device_id}
        await self._send_request(url=url, method='PUT', json=json)

    async def authenticate(self, phone: str) -> AuthenticateResponse:
        """
        Initiates authentication by sending an SMS OTP.

        :param phone: The phone number to receive the SMS OTP.
                      Must start by the country code without +
        """
        url = urljoin(self._sber_uapi_url, 'authenticate')
        json = {
            'identifier': {
                'type': 'phone',
                'data': {
                    'value': phone
                }
            },
            'authenticator': {
                'type': 'sms_otp',
                'data': {}
            },
            'channel': {
                'type': 'web',
                'user_type': 'private',
                'data': {
                    'rsa_data': self._rsa_data,
                    'oidc': self._oidc,
                    'browser': 'Chrome',
                    'os': 'Android 10'
                }
            }
        }
        response = await self._send_request(url=url, method='POST', json=json, headers=self._headers)
        return AuthenticateResponse(**response)

    async def verify(self, ouid: str, sms_otp: Union[str, int]) -> VerifyResponse:
        """
        Verifies the received SMS OTP and OUID to obtain an authentication code.

        :param ouid: Unique identifier received from authenticate().
        :param sms_otp: One-time password received via SMS.
        """
        url = urljoin(self._sber_uapi_url, 'verify')
        json = {
            'identifier': {
                'type': 'ouid',
                'data': {
                    'value': ouid
                }
            },
            'authenticator': {
                'type': 'sms_otp',
                'data': {
                    'value': str(sms_otp)
                }
            },
            'channel': {
                'type': 'web',
                'data': {
                    'rsa_data': self._rsa_data,
                    'oidc': self._oidc,
                    'browser': 'Chrome',
                    'os': 'Android 10',
                    'set_cookie': False
                }
            }
        }
        response = await self._send_request(url=url, method='POST', json=json, headers=self._headers)
        return VerifyResponse(**response['response_data'])

    async def get_access_token(self, authcode: str) -> AccessTokenResponse:
        """
        Exchanges the authentication code for an access token.

        :param authcode: Authentication code received from verify().
        """
        data = {
            'code': authcode,
            'code_verifier': self._code_verifier,
            'client_id': self._client_id,
            'redirect_uri': 'companionapp://host',
            'grant_type': 'authorization_code'
        }
        return await self._get_access_token(data=data)

    async def get_device_groups(self) -> DeviceGroups:
        url = urljoin(self._sber_devices_url, 'device_groups')
        response = await self._send_request(url=url)
        return DeviceGroups(**response)

    async def get_device_group_tree(self, group_id: str) -> DeviceGroupTree:
        """
        Retrieves the device group tree for the specified group.

        :param group_id: Group ID obtained from get_device_groups().
        """
        url = urljoin(self._sber_devices_url, f'device_groups/tree?id={group_id}')
        response = await self._send_request(url=url)
        return DeviceGroupTree(**response['result'])

    async def get_device(self, device_id: str) -> SberSmartBulb:
        """
        Retrieves the state of a specific device.

        :param device_id: Device ID obtained from get_device_group_tree().
        """
        url = urljoin(self._sber_devices_url, f'devices/{device_id}/state')
        response = await self._send_request(url=url)
        return SberSmartBulb(**response)

    async def set_white(self, device_id: str, brightness: int, temp: int):
        """
        :param device_id: Device ID obtained from get_device_group_tree().
        :param brightness: min 5, max 100
        :param temp: min 0, max 100
        """
        WhiteValidation(brightness=brightness, temp=temp)
        states = [
            {'key': 'light_mode', 'type': 'ENUM', 'enum_value': 'white'},
            {'key': 'light_brightness', 'type': 'INTEGER', 'integer_value': brightness * 10},
            {'key': 'light_colour_temp', 'type': 'INTEGER', 'integer_value': temp * 10}
        ]
        await self._set_states(device_id=device_id, states=states)

    async def set_color(self, device_id: str, h: int, s: int, v: int):
        """
        HSV (HSB) color model

        :param device_id: Device ID obtained from get_device_group_tree().
        :param h: hue, min 0, max 360
        :param s: saturation, min 0, max 100
        :param v: value (brightness), min 0, max 100
        """
        ColorValidation(h=h, s=s, v=v)
        states = [
            {'key': 'light_mode', 'type': 'ENUM', 'enum_value': 'colour'},
            {
                'key': 'light_colour',
                'colour_value': {'h': h, 's': s * 10, 'v': v * 10},
                'string_value': '{' + f'"h":{h},"s":{s * 10},"v":{v * 10}' + '}'
            }
        ]
        await self._set_states(device_id=device_id, states=states)

    async def set_scene(self, device_id: str, scene: DeviceSceneEnum):
        """
        :param device_id: Device ID obtained from get_device_group_tree().
        :param scene: candle | arctic | romantic | dawn | sunset | christmas | fito
        """
        SceneValidation(scene=scene)
        states = [
            {'key': 'light_mode', 'type': 'ENUM', 'enum_value': 'scene'},
            {'key': 'light_scene', 'enum_value': scene, 'type': 'ENUM'}
        ]
        await self._set_states(device_id=device_id, states=states)

    async def set_timer(self, device_id: str, minutes: int):
        """
        :param device_id: Device ID obtained from get_device_group_tree().
        :param minutes: min 0, max 1440
        """
        TimerValidation(minutes=minutes)
        states = [
            {'key': 'sleep_timer', 'type': 'INTEGER', 'integer_value': minutes * 60}
        ]
        await self._set_states(device_id=device_id, states=states)

    async def set_on_off(self, device_id: str, value: bool):
        """
        :param device_id: Device ID obtained from get_device_group_tree().
        :param value: True - on, False - off
        """
        states = [
            {'key': 'on_off', 'bool_value': value, 'type': 'BOOL'}
        ]
        await self._set_states(device_id=device_id, states=states)

    async def get_device_states(self, device_id: str) -> DeviceStates:
        device = await self.get_device(device_id=device_id)
        return DeviceStates.from_reported_state(reported_state=device.reported_state)

    async def close(self):
        await self.session.close()
