from base64 import b64encode
from collections import namedtuple
from typing import Tuple
from uuid import UUID

from Cryptodome.Cipher import ChaCha20_Poly1305
from Cryptodome.Hash import SHA3_256, HMAC
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes
from proto import Message, Field, BYTES

from one_manager.utils import get_master_key


class Secret(Message):
    """
    Protobuf Serializer class
    """
    cipher_text = Field(BYTES, number=1)
    nonce = Field(BYTES, number=2)
    tag = Field(BYTES, number=3)


class Cryptography:
    """
    Performs all Cryptographic related tasks
    """
    __SecretKey__: bytes = get_master_key()
    CipherText = namedtuple("CipherText", ["nonce", "cipher_text", "tag"])

    @staticmethod
    def hmac_password(password: str) -> bytes:
        """
        Hashes the password to store in the database
        :param password: Plain text password of the uer
        :return: Hashed password of the user
        """
        h = HMAC.new(Cryptography.__SecretKey__, digestmod=SHA3_256)
        h.update(password.encode('UTF-8'))
        return h.digest()

    @staticmethod
    def verify_hmac_password(password: str, hmac: bytes):
        """
        Verify the user password
        :param password: Plain text password of the user
        :param hmac: Hashed password of the uer
        :return: Is user authenticated
        """
        h = HMAC.new(Cryptography.__SecretKey__, digestmod=SHA3_256)
        h.update(password.encode('UTF-8'))
        try:
            h.verify(hmac)
            return True
        except ValueError as exception:
            return False

    @staticmethod
    def generate_key(user_password: str, length: int) -> bytes:
        """
        Generates keys used for ciphering and deciphering secrets and for random passwords
        :param user_password: Plaintext password of the user
        :param length: Length of the key
        :return: Key derived from password
        """
        return scrypt(user_password, get_random_bytes(16), length, N=2 ** 14, r=8, p=1)

    @staticmethod
    def generate_random_password(user_password: str) -> str:
        """
        Generates random passwords
        :param user_password: Plain text password of user
        :return:Random Password
        """
        rand_password = Cryptography.generate_key(user_password, 24)
        return b64encode(rand_password).decode('UTF-8')

    @staticmethod
    def __encrypt__(user_id: UUID, key: bytes, secret: bytes) -> Secret:
        """
        Ciphers the secret
        :param user_id: UUID of the user
        :param key: Cryptographic Key for encryption
        :param secret: Data tht needs to be encrypted
        :return: CipherText
        """
        cipher = ChaCha20_Poly1305.new(key=key, nonce=get_random_bytes(12))
        cipher.update(user_id.bytes)
        cipher_text, tag = cipher.encrypt_and_digest(secret)
        return Secret(nonce=cipher.nonce, cipher_text=cipher_text, tag=tag)

    def __encrypt_key__(user_id: UUID, key: bytes) -> Secret:
        """
        Ciphers the generated key for storing in database
        :param key: Key that needs to encrypted
        :return: CipherText
        """
        return Cryptography.__encrypt__(user_id=user_id, key=Cryptography.__SecretKey__, secret=key)

    @staticmethod
    def encrypt(user_id: UUID, user_password: str, secret: bytes) -> Tuple[Secret, Secret]:
        """
        Ciphers the secret
        :param user_id: UUID of the user
        :param user_password: Plain text password of user
        :param secret: Data tht needs to be encrypted
        :return: CipherText of both key and data
        """
        key = Cryptography.generate_key(user_password=user_password, length=32)
        cipher_text = Cryptography.__encrypt__(user_id=user_id, key=key, secret=secret)
        return Cryptography.__encrypt_key__(user_id=user_id, key=key), cipher_text

    @staticmethod
    def decrypt(user_id: UUID, key: Secret, secret: Secret) -> bytes:
        """
        Deciphers the secrets
        :param user_id: UUID of the user
        :param key: Cryptographic key for deciphering
        :param secret:
        :return: Data
        """
        cipher = ChaCha20_Poly1305.new(key=Cryptography.__SecretKey__, nonce=key.nonce)
        cipher.update(user_id.bytes)
        key = cipher.decrypt_and_verify(key.cipher_text, received_mac_tag=key.tag)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=secret.nonce)
        cipher.update(user_id.bytes)
        return cipher.decrypt_and_verify(secret.cipher_text, received_mac_tag=secret.tag)

    @staticmethod
    def serialize_secret(instance: Secret) -> bytes:
        """
        Serialize the Secret o that it could be stored in database
        :param instance: Secret instance that needs to be serialized
        :return: Serialized text
        """
        return Secret.serialize(instance)

    @staticmethod
    def deserialize_secret(payload: bytes) -> Secret:
        """
        Deserialized the text
        :param payload: Serialized text
        :return: Secret
        """
        return Secret.deserialize(payload=payload)
