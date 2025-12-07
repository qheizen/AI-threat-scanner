from database.database_connector import db
from ..utils.tools import sanitize_sql_string
from ..utils import logger

_logger = logger.get_module_logger("FileTypeMapper")


class FileType:

    def __init__(
        self, id: int = -1, name: str = "", extension: str = "", created_by: int = 0
    ):
        self.id = id
        self.name = name
        self.extension = extension
        self.created_by = created_by

    @classmethod
    def from_dict(cls, data: dict) -> "FileType":
        return cls(
            id=data.get("id", -1),
            name=data.get("name", ""),
            extension=data.get("extension", ""),
            created_by=data.get("createdBy", 0),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "extension": self.extension,
            "createdBy": self.created_by,
        }


class FileTypeMapper:

    @staticmethod
    def get_file_type_with_name(name: str) -> FileType:
        sanitized_name = sanitize_sql_string(name)
        if answer := db.search_db(
            "SELECT * FROM FileTypes WHERE name = '%s'" % sanitized_name
        ):
            file_type = FileType.from_dict(answer[0])
            return file_type

    @staticmethod
    def get_file_types_from_user_id(id: int) -> list[FileType]:
        if answer := db.search_db("SELECT * FROM FileTypes WHERE createdBy = %d" % id):
            return [FileType.from_dict(row) for row in answer]

    @staticmethod
    def get_all() -> list[FileType]:
        if answer := db.search_db("SELECT * FROM FileTypes"):
            return [FileType.from_dict(row) for row in answer]

    @staticmethod
    def delete_file_type_with_id(id: int):
        db.write_db("DELETE FROM FileTypes WHERE id = %d" % id)

    @staticmethod
    def delete_file_type_with_name(name: str):
        sanitized_name = sanitize_sql_string(name)
        db.write_db("DELETE FROM FileTypes WHERE name = '%s'" % sanitized_name)

    @staticmethod
    def create(type: FileType) -> bool:
        if isinstance(type, dict):
            type = FileType.from_dict(type)

        if FileTypeMapper.get_file_type_with_name(type.name):
            _logger.error(f"Record {type.name} already exists!")
            return False

        sql_request = (
            "INSERT INTO FileTypes (name, extension, createdBy) VALUES ('%s', '%s', %s)"
        )
        request = sql_request % (
            sanitize_sql_string(type.name),
            sanitize_sql_string(type.extension),
            int(type.created_by),
        )
        try:
            db.write_db(request)
            return FileTypeMapper.get_file_type_with_name(type.name)

        except Exception as e:
            _logger.error(f"SQLite Error: {e}")
            return False
        
    @staticmethod
    def update(id: int, data: dict) -> bool:
        set_parts = []
        params = []
        
        for field, value in data.items():
            if isinstance(value, str):
                set_parts.append(f"{field} = '%s'")
                params.append(sanitize_sql_string(value))
            else:
                set_parts.append(f"{field} = %s")
                params.append(str(value))
        
        if not set_parts:
            return False
            
        sql = f"UPDATE FileTypes SET {', '.join(set_parts)} WHERE id = {id}"
        
        try:
            db.write_db(sql % tuple(params))
            return True
        except:
            return False