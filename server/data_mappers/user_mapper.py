from database.database_connector import db
from ..utils.tools import sanitize_sql_string
from ..utils import logger

_logger = logger.get_module_logger("UserMapper")


class User:

    def __init__(self, id: int = -1, name: str='', email: str='', login: str='', password: str='',
                 can_create: int=0, can_update: int=0, can_delete: int=0, can_read: int=0,
                 registered: int=0, registration_token: str=''):
        self.id = id
        self.name = name
        self.email = email
        self.login = login
        self.password = password
        self.can_create = bool(can_create)
        self.can_update = bool(can_update)
        self.can_delete = bool(can_delete)
        self.can_read = bool(can_read)
        self.registered = bool(registered)
        self.registration_token = registration_token

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(
            id=data.get("id", -1),
            name=data.get("name", ""),
            email=data.get("email", ""),
            login=data.get("login", ""),
            password=data.get("password", ""),
            can_create=data.get("can_create", 0),
            can_update=data.get("can_update", 0),
            can_delete=data.get("can_delete", 0),
            can_read=data.get("can_read", 0),
            registered=data.get("registered", 0),
            registration_token=data.get("registrationToken", ""),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "login": self.login,
            "password": self.password,
            "can_create": int(self.can_create),
            "can_update": int(self.can_update),
            "can_delete": int(self.can_delete),
            "can_read": int(self.can_read),
            "registered": int(self.registered),
            "registrationToken": self.registration_token,
        }


class UserMapper:

    @staticmethod
    def get_user_with_id(id: int) -> User:
        if answer := db.search_db("SELECT * FROM Users WHERE id = %d" % id):
            user = User.from_dict(answer[0])
            return user
        return None

    @staticmethod
    def get_user_with_login(login: str) -> User:
        sanitized_login = sanitize_sql_string(login)
        if answer := db.search_db(
            "SELECT * FROM Users WHERE login = '%s'" % sanitized_login
        ):
            user = User.from_dict(answer[0])
            return user
        return None

    @staticmethod
    def get_user_with_token(token: str) -> User:
        sanitized_token = sanitize_sql_string(token)
        if answer := db.search_db(
            "SELECT * FROM Users WHERE registrationToken = '%s'" % sanitized_token
        ):
            user = User.from_dict(answer[0])
            return user
        return None

    @staticmethod
    def get_all() -> list[User]:
        if answer := db.search_db("SELECT * FROM Users"):
            return [User.from_dict(row) for row in answer]

    @staticmethod
    def delete_user_with_id(id: int):
        db.write_db("DELETE FROM Users WHERE id = %d" % id)

    @staticmethod
    def create(user: User) -> bool:
        if isinstance(user, dict):
            user = User.from_dict(user)

        if UserMapper.get_user_with_login(user.login):
            _logger.error(f"Record {user.login} already exists!")
            return False

        sql_request = "INSERT INTO Users (name, email, login, password, can_create, can_update, can_delete, can_read, registered, registrationToken) VALUES (%s, '%s', '%s', '%s', '%s', %s, %s, %s, %s, %s, '%s')"
        request = sql_request % (
            sanitize_sql_string(user.name),
            sanitize_sql_string(user.email),
            sanitize_sql_string(user.login),
            sanitize_sql_string(user.password),
            int(user.can_create),
            int(user.can_update),
            int(user.can_delete),
            int(user.can_read),
            int(user.registered),
            sanitize_sql_string(user.registration_token),
        )

        try:
            db.write_db(request)
            return UserMapper.get_user_with_login(user.login)

        except Exception as e:
            _logger.error(f"SQLite Error: {e}")
            return False
