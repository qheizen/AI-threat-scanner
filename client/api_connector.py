import json
import requests
import traceback
from .utils import logger
from .utils import const
from .ai_core.ai_embeddings import embedding_to_str, embedding_from_str
from .ai_core.ai_model import FileEmbedding
from functools import wraps



_logger = logger.get_module_logger("API")

def catcher(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            traceback_msg = traceback.format_exc()
            _logger.error(f"Something at {func.__name__}\nExc: {e}\n{traceback_msg}")
            
            return False
    return wrapper


class Client:

    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.online = False
        self.user_id: int | None = None
        self.email: str = ""

    @catcher
    def authorization(self) -> bool:
        try:
            requests.post(const.ONLINE_URL, json={})
        except:
            _logger.error("Service is not online!")
            return False
            
        data = {"login": self.login, "password": self.password}
        resp = requests.post(const.AUTH_URL, json=data)
        try:
            resp.raise_for_status()
        except Exception as e:
            _logger.error(f"Something wrong {e}")
            return False
        
        response = resp.json()

        if int(response.get("STATUS", 500)) == 200:
            resp_data = response.get("RESP", {})
            
            if isinstance(resp_data, list) and resp_data:
                resp_data = resp_data[0]
            self.user_id = resp_data.get("id")
            self.email = resp_data.get("email", "")
            self.online = True
            _logger.info(f"User exist! Excellent!")
            return True
        return False

    @classmethod
    @catcher
    def create_user(cls, login: str, password: str, name: str, email: str = ""):
        try:
            requests.post(const.ONLINE_URL, json={})
        except:
            _logger.error("Service is not online!")
            return False
        
        user = cls(login, password)
        
        if user.authorization():
            return user

        data = {"name": name, "email": email, "login": login, "password": password}
        resp = requests.post(const.CREATE_USER_URL, json=data)
        resp.raise_for_status()
        resp_json = resp.json()

        status = int(resp_json.get("STATUS", 500))
        if status == 200:
            resp_data = resp_json.get("RESP", {})
            if isinstance(resp_data, list) and resp_data:
                resp_data = resp_data[0]
            user.email = resp_data.get("email", "")
            user.user_id = resp_data.get("id")
            _logger.info(f"User created! name = {name}, email = {email}, id = {user.user_id}")
            return user

        return False

    @catcher
    def search(self, filters: dict, table: str):
        if not self.online:
            _logger.error("User is not online!")
            return False
        
        payload = {
            "data": filters or {},
            "table": table,
            "login": self.login,
            "password": self.password
        }

        
        if "user_id" in payload["data"]:
            payload["data"]["user_id"] = self.user_id

        resp = requests.post(const.SEARCH_URL, json=payload)
        resp.raise_for_status()
        resp_json = resp.json()

        status = int(resp_json.get("STATUS", 500))
        if status == 200:
            return resp_json.get("RESP", [])
        return False

    @catcher
    def update(self, data: dict | list, table: str):
        if not self.online:
            _logger.error("User is not online!")
            return False
        
        payload = {
            "data": [data] if isinstance(data, dict) else data,
            "table": table,
            "login": self.login,
            "password": self.password
        }

        resp = requests.post(const.UPDATE_URL, json=payload)
        resp.raise_for_status()
        resp_json = resp.json()

        status = int(resp_json.get("STATUS", 500))
        if status == 200:
            return resp_json.get("RESP", {})
        return False

    @catcher
    def create(self, data: dict | list, table: str):
        if not self.online:
            _logger.error("User is not online!")
            return False
        
        payload = {
            "data": [data] if isinstance(data, dict) else data,
            "table": table,
            "login": self.login,
            "password": self.password
        }

        resp = requests.post(const.CREATE_URL, json=payload)
        resp.raise_for_status()
        resp_json = resp.json()

        status = int(resp_json.get("STATUS", 500))
        if status == 200:
            return resp_json.get("RESP", [])
        return False

    @catcher
    def delete(self, data, table: str):
        if not self.online:
            _logger.error("User is not online!")
            return False
        
        payload = {
            "data": data,
            "table": table,
            "login": self.login,
            "password": self.password
        }

        
        resp = requests.post(const.DELETE_URL, json=payload)
        resp.raise_for_status()
        resp_json = resp.json()

        status = int(resp_json.get("STATUS", 500))
        if status == 200:
            return True
        return False

    def create_new_filetype(self, name: str, extension: str):
        data_to_create = {
            "name": name,
            "extension": extension,
            "createdBy": self.user_id
        }
        return self.create(data_to_create, "FileType")

    def create_new_threattype(self, name: str, description: str):
        data_to_create = {
            "threatName": name,
            "threatDescription": description,
            "createdBy": self.user_id
        }
        return self.create(data_to_create, "ThreatType")

    def create_new_threatfiles(self, threatfiles: list[FileEmbedding]):
        data_to_create = []
        for file in threatfiles:

            file_type_search = {"extension": file.file_type}
            ft_search_res = self.search(file_type_search, "FileType") or []
            if ft_search_res:
                file_type_id = ft_search_res[0].get('id')
            else:
                file_type_create = {
                    "name": file.file_type, "extension": file.file_type, "createdBy": self.user_id}
                created = self.create(file_type_create, "FileType") or []
                file_type_id = created[0].get('id') if created else None

            threat_type_search = {"threatName": file.threat_type}
            tt_search_res = self.search(threat_type_search, "ThreatType") or []
            if tt_search_res:
                threat_type_id = tt_search_res[0].get('id')
            else:

                threat_type_create = {"threatName": file.threat_type,
                                      "threatDescription": "", "createdBy": self.user_id}
                created_tt = self.create(
                    threat_type_create, "ThreatType") or []
                threat_type_id = created_tt[0].get(
                    'id') if created_tt else None

            data_to_create.append({
                "fileName": file.file_name,
                "sha256": file.sha256,
                "fileEmbedding": embedding_to_str(file.file_embedding),
                "threat_type_id": threat_type_id,
                "file_type_id": file_type_id,
                "fileVerdict": file.file_verdict,
                "createdBy": self.user_id
            })

        return self.create(data_to_create, "ThreateningFiles")

    @catcher
    def get_train_data(self) -> list[FileEmbedding]:
        data = self.search({}, "ThreateningFiles") or []
        result = []
        for emb in data:

            ft = self.search({"id": emb.get("file_type_id")}, "FileType") or []
            tt = self.search(
                {"id": emb.get("threat_type_id")}, "ThreatType") or []

            file_type_name = ft[0].get('extension', "None") if ft else "None"
            threat_type_name = tt[0].get(
                'threatName', "None") if tt else "None"

            result.append(FileEmbedding(
                file_name=emb.get("fileName") or emb.get("file_name"),
                sha256=emb.get("sha256"),
                file_embedding=embedding_from_str(
                    emb.get("fileEmbedding") or emb.get("file_embedding")),
                threat_type=threat_type_name,
                file_type=file_type_name,
                file_verdict=emb.get("fileVerdict") or emb.get("file_verdict")
            ))
        return result

    @catcher
    def search_file_with_sha(self, file: FileEmbedding):
        data = self.search({"sha256": file.sha256}, "ThreateningFiles") or []
        if data:
            row = data[0]
            ft = self.search({"id": row.get("file_type_id")}, "FileType") or []
            tt = self.search(
                {"id": row.get("threat_type_id")}, "ThreatType") or []

            file.file_embedding = embedding_from_str(
                row.get('fileEmbedding') or row.get('file_embedding'))
            file.file_type = ft[0].get('extension', "None") if ft else "None"
            file.threat_type = tt[0].get(
                'threatName', "None") if tt else "None"
            file.file_verdict = row.get(
                "fileVerdict") or row.get("file_verdict")
            return file

        return False

cl = Client.create_user("admin", "admin", "admin", "admin@gmail.com")
while True:
    eval(str(input()))
    
    
