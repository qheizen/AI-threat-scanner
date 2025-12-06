from database.database_connector import db
from ..utils.tools import sanitize_sql_string
from ..utils import logger
from datetime import datetime

_logger = logger.get_module_logger("ThreateningFileMapper")


class ThreateningFile:

    def __init__(
        self, id: int = -1, file_name: str = "", sha256: str = "", file_embedding: str = "", threat_type_id: int = 0, creation_date: str = "", created_by: int = 0,
    ):
        self.id = id
        self.file_name = file_name
        self.sha256 = sha256
        self.file_embedding = file_embedding
        self.threat_type_id = threat_type_id
        self.creation_date = creation_date
        self.created_by = created_by

    @classmethod
    def from_dict(cls, data: dict) -> "ThreateningFile":
        return cls(
            id=data.get("id", -1),
            file_name=data.get("fileName", ""),
            sha256=data.get("sha256", ""),
            file_embedding=data.get("fileEmbedding", ""),
            threat_type_id=data.get("threatType_id", 0),
            creation_date=data.get("creationDate", ""),
            created_by=data.get("createdBy", 0),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "fileName": self.file_name,
            "sha256": self.sha256,
            "fileEmbedding": self.file_embedding,
            "threatType_id": self.threat_type_id,
            "creationDate": self.creation_date,
            "createdBy": self.created_by,
        }


class ThreateningFileMapper:

    @staticmethod
    def get_file_with_id(id: int) -> ThreateningFile:
        if answer := db.search_db("SELECT * FROM ThreateningFiles WHERE id = %d" % id):
            file = ThreateningFile.from_dict(answer[0])
            return file

    @staticmethod
    def get_file_with_sha256(sha256: str) -> ThreateningFile:
        sanitized_sha256 = sanitize_sql_string(sha256)
        if answer := db.search_db(
            "SELECT * FROM ThreateningFiles WHERE sha256 = '%s'" % sanitized_sha256
        ):
            file = ThreateningFile.from_dict(answer[0])
            return file

    @staticmethod
    def get_files_from_user_id(id: int) -> list[ThreateningFile]:
        if answer := db.search_db(
            "SELECT * FROM ThreateningFiles WHERE createdBy = %d" % id
        ):
            return [ThreateningFile.from_dict(row) for row in answer]

    @staticmethod
    def get_files_from_threat_type_id(threat_type_id: int) -> list[ThreateningFile]:
        if answer := db.search_db(
            "SELECT * FROM ThreateningFiles WHERE threatType_id = %d" % threat_type_id
        ):
            return [ThreateningFile.from_dict(row) for row in answer]

    @staticmethod
    def get_all() -> list[ThreateningFile]:
        if answer := db.search_db("SELECT * FROM ThreateningFiles"):
            return [ThreateningFile.from_dict(row) for row in answer]

    @staticmethod
    def delete_file_with_id(id: int):
        db.write_db("DELETE FROM ThreateningFiles WHERE id = %d" % id)

    @staticmethod
    def delete_file_with_sha256(sha256: str):
        sanitized_sha256 = sanitize_sql_string(sha256)
        db.write_db(
            "DELETE FROM ThreateningFiles WHERE sha256 = '%s'" % sanitized_sha256
        )

    @staticmethod
    def create(file: ThreateningFile) -> bool:
        if isinstance(file, dict):
            file = ThreateningFile.from_dict(file)

        if ThreateningFileMapper.get_file_with_sha256(file.sha256):
            _logger.error(f"File with SHA256 {file.sha256} already exists!")
            return False

        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sql_request = "INSERT INTO ThreateningFiles (fileName, sha256, fileEmbedding, threatType_id, creationDate, createdBy) VALUES ('%s', '%s', '%s', %s, '%s', %s)"
        request = sql_request % (
            sanitize_sql_string(file.file_name),
            sanitize_sql_string(file.sha256),
            sanitize_sql_string(file.file_embedding),
            int(file.threat_type_id),
            current_date, 
            int(file.created_by),
        )
        try:
            db.write_db(request)
            return ThreateningFileMapper.get_file_with_sha256(file.sha256)

        except Exception as e:
            _logger.error(f"SQLite Error: {e}")
            return False

    @staticmethod
    def update_file_embedding(file_id: int, embedding: str) -> bool:
        sanitized_embedding = sanitize_sql_string(embedding)
        try:
            db.write_db(
                "UPDATE ThreateningFiles SET fileEmbedding = '%s' WHERE id = %d" % (sanitized_embedding, file_id)
            )
            return True
        except Exception as e:
            _logger.error(f"Error updating file embedding: {e}")
            return False
