import winreg
from winreg import OpenKeyEx, QueryValueEx, CloseKey, HKEY_CURRENT_USER, CreateKey, SetValueEx

from Cryptodome.Random import get_random_bytes


def generate_master_key():
    """
    Stores Master Key to Windows Registry
    :return: None
    """
    print("Setup")
    path = OpenKeyEx(HKEY_CURRENT_USER, r'SOFTWARE\\')
    app_path = CreateKey(path, "OneManager")
    SetValueEx(app_path, "MASTER_KEY", 0, winreg.REG_BINARY, get_random_bytes(32))
    CloseKey(app_path)
    CloseKey(path)


def get_master_key() -> bytes:
    """
    Retrieve the master key from the Registry
    :return:
    """
    path = OpenKeyEx(HKEY_CURRENT_USER, r'SOFTWARE\\OneManager')
    masterkey = QueryValueEx(path, 'MASTER_KEY')
    CloseKey(path)
    return masterkey[0]
