class HKEYType: ...

HKEY_CURRENT_USER: HKEYType
KEY_SET_VALUE: int
REG_SZ: int

def CreateKeyEx(
    key: HKEYType,
    sub_key: str,
    reserved: int = 0,
    access: int = 0,
) -> HKEYType: ...
def SetValueEx(
    key: HKEYType,
    value_name: str,
    reserved: int,
    type: int,
    value: str,
) -> None: ...
def CloseKey(key: HKEYType) -> None: ...
def DeleteKey(key: HKEYType, sub_key: str) -> None: ...
