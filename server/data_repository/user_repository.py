from ..data_mappers.user_mapper import UserMapper, User
from ..utils import logger
import random
import hashlib

_logger = logger.get_module_logger("UserRepository")


class UserRepository:

    @staticmethod
    def autentification(login: str, password: str) -> bool:
        if user := UserRepository.search(login=login):
            hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()
            return user.password == hashed_password
        _logger.error(f"Record with {login} undefined")
        return False

    @staticmethod
    def authorization(login: str) -> list:
        if user := UserRepository.search(login=login):
            return [user.can_create, user.can_read, user.can_update, user.can_delete]

    @staticmethod
    def create(user_data: dict) -> User:
        if any(key not in user_data for key in ["password", "login", "name"]):
            _logger.error(f"Record corrupted {user_data}")
            return None

        user_data["password"] = hashlib.sha256(
            user_data["password"].encode("utf-8")
        ).hexdigest()
        user_data["registrationToken"] = hashlib.sha256(
            random.Random.getrandbits(256)
        ).hexdigest()
        return UserMapper.create(user_data)

    @staticmethod
    def search(login: str = None, id: int = None) -> User:
        if login:
            return UserMapper.get_user_with_login(login)
        elif id:
            return UserMapper.get_user_with_id(id)
        else:
            return UserMapper.get_all()

    @staticmethod
    def delete(id: int = None, login: str = None) -> bool:
        if login and (user := UserRepository.search(login=login)):
            return UserMapper.delete_user_with_id(user.id)
        elif id:
            return UserMapper.delete_user_with_id(id)
        return False
