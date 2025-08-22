from datetime import datetime
from enum import Enum
from typing import (Any,
                    Dict,
                    List,
                    Optional,
                    Union)

from pydantic import (BaseModel,
                      Field,
                      conint)


class AuthenticatorData(BaseModel):
    phones: List[str]


class Authenticator(BaseModel):
    type: str
    lifetime: int
    data: AuthenticatorData
    attempts_remaining: int
    initialization_required: bool


class AuthenticateResponse(BaseModel):
    authenticator: List[Authenticator]
    ouid: str


class VerifyResponse(BaseModel):
    redirect_uri: str
    authcode: str
    state: str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    id_token: str
    refresh_token: str


class JWTTokenState(BaseModel):
    status: int


class JWTTokenResponse(BaseModel):
    state: JWTTokenState
    token: str


class DeviceOwner(BaseModel):
    account_id: str
    guest_ids: List[str]
    linked_account_id: str
    is_owner: bool


class DeviceGroup(BaseModel):
    id: str
    meta: Optional[Any] = None
    parent_id: str
    name: str
    owner_info: DeviceOwner
    group_type: str
    address: str
    images: Dict[str, Any]
    widgets: Optional[List[Any]] = None
    image_set_type: str
    settings: Optional[Any] = None
    names: Dict[str, str]
    image_set_types: Dict[str, str]
    geo_position: Optional[Any] = None
    has_geo_position: bool
    address_details: Optional[Any] = None


class Pagination(BaseModel):
    limit: int
    offset: int
    total: int


class DeviceGroups(BaseModel):
    result: List[DeviceGroup]
    pagination: Pagination


class DeviceName(BaseModel):
    name: str
    default_name: str = Field(alias="defaultName")
    nicknames: List[str]
    names: Dict[str, Any]


class DeviceModeEnum(str, Enum):
    white = 'white'
    colour = 'colour'
    scene = 'scene'
    music = 'music'
    adaptive = 'adaptive'


class DeviceSceneEnum(str, Enum):
    candle = 'candle'
    arctic = 'arctic'
    romantic = 'romantic'
    sunset = 'sunset'
    dawn = 'dawn'
    christmas = 'christmas'
    fito = 'fito'


class DeviceRange(BaseModel):
    min: int
    max: int
    step: int


class DeviceIntValues(BaseModel):
    range: DeviceRange
    unit: str


class DeviceColorValues(BaseModel):
    h: DeviceRange
    s: DeviceRange
    v: DeviceRange


class DeviceEnumValues(BaseModel):
    values: List[Union[DeviceModeEnum, DeviceSceneEnum]]


class DeviceAttribute(BaseModel):
    key: str
    meta: Optional[Any] = None
    type: str
    int_values: Optional[DeviceIntValues] = None
    float_values: Optional[float] = None
    string_values: Optional[str] = None
    enum_values: Optional[DeviceEnumValues] = None
    name: str
    color_values: Optional[DeviceColorValues] = None
    depends_on: Optional[str] = None
    is_visible: bool
    min_version: str


class DeviceInfo(BaseModel):
    manufacturer: str
    model: str
    hw_version: str
    sw_version: str
    description: str
    product_id: str
    partner: str
    sw_version_int: int


class DeviceColorState(BaseModel):
    h: int
    s: int
    v: int


class DeviceState(BaseModel):
    key: str
    type: str
    float_value: float
    integer_value: int
    string_value: str
    bool_value: bool
    enum_value: str
    color_value: Optional[DeviceColorState] = None
    last_sync: Optional[datetime] = None


class DeviceCommand(BaseModel):
    key: str
    state_fields: List[str]
    exceptions: List


class DeviceFullCategory(BaseModel):
    id: str
    meta: Optional[Any] = None
    name: str
    images: Dict
    slug: str
    widgets: List
    default_name: str
    image_set_type: str
    names: Dict
    default_names: Dict
    sort_weight: int


class Device(BaseModel):
    id: str
    meta: Optional[Any] = None
    routing_key: str
    device_type_id: str
    parent_id: str
    name: DeviceName
    device_info: DeviceInfo
    attributes: List[DeviceAttribute]
    reported_state: List[DeviceState]
    desired_state: List[DeviceState]
    commands: List[DeviceCommand]
    sync_info: Optional[Any] = None
    serial_number: str
    external_id: str
    owner_info: DeviceOwner
    images: Dict[str, str]
    categories: List[str]
    group_ids: List[str]
    bridge_meta: Dict
    device_type_name: str
    correction: Optional[Any] = None
    hw_version: str
    sw_version: str
    dependencies: Dict
    full_categories: List[DeviceFullCategory]
    widgets: List
    image_set_type: str
    children: Optional[Any] = None
    linked: List
    connection_type: str
    coprocessor_fw_version: str
    channel: int
    wifi_bssid: str
    local_info: Optional[Any] = None


class DeviceGroupTree(BaseModel):
    group: DeviceGroup
    children: List
    devices: List[Device]
    status: List[Dict[str, Any]]


class SberSmartBulb(BaseModel):
    device_id: str
    reported_state: List[DeviceState]
    timestamp: datetime


class DeviceStates(BaseModel):
    online: bool
    on_off: bool
    work_mode: DeviceModeEnum
    light_scene: DeviceSceneEnum
    bright_value_v2: int
    temp_value_v2: int
    colour_data_v2: DeviceColorState
    sleep_timer: int

    @classmethod
    def from_reported_state(cls, reported_state: List[DeviceState]) -> 'DeviceStates':
        states = {}
        for state in reported_state:
            if state.key in cls.model_fields:
                value = None
                if state.type == 'BOOL':
                    value = state.bool_value
                if state.type == 'ENUM':
                    value = state.enum_value
                if state.key == 'bright_value_v2':
                    value = state.integer_value // 10 or 5
                if state.key == 'temp_value_v2':
                    value = state.integer_value // 10
                if state.key == 'colour_data_v2':
                    data = state.color_value
                    value = {'h': data.h, 's': data.s // 10, 'v': data.v // 10}
                if state.key == 'sleep_timer':
                    value = state.integer_value // 60
                states[state.key] = value
        return cls(**states)


class TimerValidation(BaseModel):
    minutes: conint(ge=0, le=1440)


class SceneValidation(BaseModel):
    scene: DeviceSceneEnum


class ColorValidation(BaseModel):
    h: conint(ge=0, le=360)
    s: conint(ge=0, le=100)
    v: conint(ge=0, le=100)


class WhiteValidation(BaseModel):
    brightness: conint(ge=5, le=100)
    temp: conint(ge=0, le=100)
