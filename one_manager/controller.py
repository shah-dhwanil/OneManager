from uuid import UUID

from psycopg import Connection
from psycopg.errors import NoDataFound

from one_manager.cryptography import Cryptography


class DatabaseController:
    """
    Manages all database operations
    """

    @staticmethod
    def setup(conn: Connection):
        """
        Setups the database for the application
        :param conn: Connection to database
        :return:
        """
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
        id UUID DEFAULT gen_random_uuid(),
        username VARCHAR(32) NOT NULL,
        password bytea NOT NULL,
        CONSTRAINT pk_user_id PRIMARY KEY(id),
        CONSTRAINT unique_user_username UNIQUE(username)
        );

        CREATE TABLE IF NOT EXISTS secret(
            id UUID DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL,
            name VARCHAR(32) NOT NULL,
            secret bytea NOT NULL,
            hash bytea NOT NULL,
            CONSTRAINT pk_secret_id PRIMARY KEY(id),
            CONSTRAINT unique_name_user UNIQUE(name,user_id),
            CONSTRAINT unique_secrets_secret_hash UNIQUE(secret,hash)
        );

        CREATE TABLE IF NOT EXISTS store(
            id UUID DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL,
            secret bytea NOT NULL,
            hash bytea NOT NULL,
            CONSTRAINT pk_store_id PRIMARY KEY(id),
            CONSTRAINT unique_store_secret_hash UNIQUE(secret,hash)
        );
        """)

    @staticmethod
    def create_user(conn: Connection, username: str, password: str):
        """
        Create user in database
        :param conn: Connection to database
        :param username: Username of the user
        :param password: Password of the user
        :return: None
        """
        conn.execute("""
        INSERT INTO users(username,password) VALUES(%s,%s);
        """, (username, Cryptography.hmac_password(password)))

    @staticmethod
    def get_user_login(conn: Connection, username: str):
        """
        Gets user hashed password for login
        :param conn: Connection to database
        :param username: Username of the user
        :return: UUID and hashed password of the user
        """
        return conn.execute("""
        SELECT id, password FROM users WHERE username=%s
        """, (username,)).fetchone()

    @staticmethod
    def create_secret(conn: Connection, user: UUID, name: str, cipher_text: bytes, hash: bytes):
        """
        Creates a secret in database
        :param conn: Connection to database
        :param user: UUID of the user
        :param name: Name of the Secret
        :param cipher_text: Cipher Text of the secret
        :param hash: Hash of the cryptographic keu
        :return: None
        """
        conn.execute("""
        INSERT INTO secret(user_id,name,secret,hash) VALUES(%s,%s,%s,%s);
        """, (user, name, cipher_text, hash))

    @staticmethod
    def create_key(conn: Connection, user: UUID, cipher_text: bytes, hash: bytes):
        """
        Creates a cryptographic key in the database
        :param conn: Connection to database
        :param user: UUID of the user
        :param cipher_text: Cipher Text of the key
        :param hash: Hash of the Secret
        :return: None
        """
        conn.execute("""
        INSERT INTO store(user_id,secret,hash) VALUES(%s,%s,%s);
        """, (user, cipher_text, hash))

    @staticmethod
    def get_secret(conn: Connection, user: UUID, name: str):
        """
        Retrieves the secret from the database
        :param conn: Connection to database
        :param user: UUID of the user
        :param name: Name of the secret
        :return: Secret of the user
        """
        return conn.execute("""
        SELECT secret,hash FROM secret WHERE user_id=%s AND name= %s
        """, (user, name)).fetchone()

    @staticmethod
    def get_key(conn: Connection, user: UUID, hash: bytes):
        """
        Retrieves the cryptographic key from the database
        :param conn: Connection to database
        :param user: UUID of the user
        :param hash: Hash of the secrets whose key is needed
        :return: Key of the following secret
        """
        return conn.execute("""
        SELECT secret FROM store WHERE user_id=%s AND hash=%s
        """, (user, hash)).fetchone()

    @staticmethod
    def update_secret(conn: Connection, user: UUID, name: str, cipher_text: bytes, hash: bytes):
        """
        Update the secret in the database
        :param conn: Connection to database
        :param user: UUID of the user
        :param name: Name of the secret that needs to be updated
        :param cipher_text: Cipher Text of updated secret
        :param hash: Hash of the cryptographic key
        :return: None
        """
        return conn.execute("""
        UPDATE secret
        SET
            secret = %s,
            hash = %s
        WHERE
            user_id=%s AND name=%s
        """, (cipher_text, hash, user, name))

    @staticmethod
    def update_key(conn: Connection, user: UUID, hash_old: bytes, cipher_text: bytes, hash_new: bytes):
        """
        Updates the key of the secret in database
        :param conn: Connection to database
        :param user: UUID of the user
        :param hash_old: Old hash of the secret
        :param cipher_text: Cipher Text of updated cryptographic key
        :param hash_new: Updated hash of the secret
        :return:None
        """
        return conn.execute("""
        UPDATE store
        SET
            secret = %s,
            hash = %s
        WHERE
            user_id=%s AND hash=%s
        """, (cipher_text, hash_new, user, hash_old))

    @staticmethod
    def delete_secret(conn: Connection, user: UUID, name: str):
        """
        Deletes the Secret from the database
        :param conn: Connection to database
        :param user: UUID of the user
        :param name: Name of the secret to be deleted
        :return: None
        """
        return conn.execute("""
        DELETE FROM secret
        WHERE
            user_id=%s AND name=%s
        """, (user, name))

    @staticmethod
    def delete_key(conn: Connection, user: UUID, hash: bytes):
        """
        Deletes the cryptographic key from the database
        :param conn: Connection to database
        :param user: UUID of the uer
        :param hash: Hash of the secret
        :return:None
        """
        return conn.execute("""
        DELETE FROM store
        WHERE
            user_id=%s AND hash=%s
        """, (user, hash))


class Controller:
    """
    Interface for executing functionalities
    """

    @staticmethod
    def create_secret(conn: Connection, user_id: UUID, user_password: str, name: str, secret: str):
        """
        Creates a secret
        :param conn: Connection to database
        :param user_id: UUID of the user
        :param user_password: Plain text password of the user
        :param name: Name of the secret
        :param secret: Data
        :return: None
        """
        key_cipher, secret_cipher = Cryptography.encrypt(user_id=user_id, user_password=user_password,
                                                         secret=secret.encode('UTF-8'))
        with conn.cursor() as cursor:
            DatabaseController.create_secret(cursor, user_id, name, Cryptography.serialize_secret(secret_cipher),
                                             key_cipher.tag)
            DatabaseController.create_key(cursor, user_id, Cryptography.serialize_secret(key_cipher), secret_cipher.tag)

    @staticmethod
    def get_secret(conn: Connection, user_id: UUID, name: str) -> str:
        """
        Retrieves the secret from the database
        :param conn: Connection to database
        :param user_id: UUID of the user
        :param name: Name of the secret
        :return: Secret
        """
        with conn.cursor() as cursor:
            secret = DatabaseController.get_secret(cursor, user_id, name)
            if secret is None:
                raise NoDataFound(f"No Secret found with name {name}")
            secret_cipher_text = Cryptography.deserialize_secret(secret[0])
            key = DatabaseController.get_key(cursor, user_id, secret_cipher_text.tag)
            if key is None:
                raise NoDataFound(f"No Secret found with name {name}")
            key_cipher_text = Cryptography.deserialize_secret(key[0])
            return Cryptography.decrypt(user_id, key_cipher_text, secret_cipher_text).decode('UTF-8')

    @staticmethod
    def update_secret(conn: Connection, user_id: UUID, user_password: str, name: str, secret: str):
        """
        Updates the Secret
        :param conn: Connection to database
        :param user_id: UUID of the user
        :param user_password: Plain text password of the user
        :param name: Name of the secret
        :param secret: Data
        :return: None
        """
        key_cipher, secret_cipher = Cryptography.encrypt(user_id=user_id, user_password=user_password,
                                                         secret=secret.encode('UTF-8'))
        with conn.cursor() as cursor:
            secret_old = DatabaseController.get_secret(cursor, user_id, name)
            if secret_old is None:
                raise NoDataFound(f"No Secret found with name {name}")
            secret_cipher_text = Cryptography.deserialize_secret(secret_old[0])
            DatabaseController.update_secret(cursor, user_id, name, Cryptography.serialize_secret(secret_cipher),
                                             key_cipher.tag)
            DatabaseController.update_key(cursor, user_id, secret_cipher_text.tag,
                                          Cryptography.serialize_secret(key_cipher), secret_cipher.tag)

    @staticmethod
    def delete_secret(conn: Connection, user_id: UUID, name: str):
        """
        Deletes the Secret
        :param conn: Connection to database
        :param user_id: UUID of the user
        :param name: Name of the secret
        :return: None
        """
        with conn.cursor() as cursor:
            secret_old = DatabaseController.get_secret(cursor, user_id, name)
            if secret_old is None:
                raise NoDataFound(f"No Secret found with name {name}")
            secret_cipher_text = Cryptography.deserialize_secret(secret_old[0])
            DatabaseController.delete_secret(conn, user_id, name)
            DatabaseController.delete_key(conn, user_id, secret_cipher_text.tag)

    @staticmethod
    def create_user(conn: Connection, username: str, password: str):
        """
        Creates user in database
        :param conn: Connection to database
        :param username: Username of the user
        :param password: Password of the user
        :return: None
        """
        with conn.cursor() as cursor:
            DatabaseController.create_user(cursor, username, password)

    @staticmethod
    def verify_password(conn: Connection, username: str, password: str):
        """
        Verify the user password for login
        :param conn: Connection to database
        :param username: Username of the user
        :param password: Password of the user
        :return: User Credentials if user is verified or False
        """
        with conn.cursor() as cursor:
            hmac = DatabaseController.get_user_login(cursor, username)
            if hmac is None:
                return False
            if Cryptography.verify_hmac_password(password, hmac[1]):
                return hmac[0]
            else:
                return False
