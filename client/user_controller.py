from .api_connector import Client
from .utils import const
import hashlib
import traceback
from pathlib import Path
from functools import wraps
from .utils import logger
from .ai_core.ai_model import FileEmbedding

_logger = logger.get_module_logger("API")


def catcher(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            traceback_msg = traceback.format_exc()
            _logger.error(
                f"Something at {func.__name__}\nExc: {e}\n{traceback_msg}")
            return False
    return wrapper

class UserController:
    
    def __init__(self):
        self.client = Client("None", "None")
    
    @catcher
    def registration(self, name: str, login: str, password: str, email: str) -> bool:
        self.client = Client.create_user(login, password, name, email)
        self.client.authorization()
        return True
    
    @catcher
    def authorization(self, login: str, password: str):
        self.client = Client(login, password)
        return True if self.client.authorization() else False
    
    @catcher
    def create_new_filetype(self, name: str, extension: str):
        self.client.create_new_filetype(name, extension)
        return True
    
    @catcher
    def create_new_threattype(self, name: str, description: str):
        self.client.create_new_threatfiles(name, description)
        return True
        
    @catcher
    def update(self, data: dict, table: str):
        return self.client.update(data, table)
        
    @catcher
    def delete(self, data: dict, table: str):
        return self.client.delete(data, table)
    
    @catcher
    def create(self, data: dict, table: str):
        return self.client.create(data, table)
        
    @catcher
    def search(self, filter: dict, table: str):
        return self.client.search(filter, table)
        
    @catcher
    def search_sha_from_file(self, file_path: str, chunk_size: int = 8192) -> FileEmbedding:
        file_path = Path(file_path)
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hasher.update(chunk)
        
        file = FileEmbedding(
            file_name=Path(file_path).name,
            sha256=hasher.hexdigest(),
        )
        return [self.client.search_file_with_sha(file)]
        