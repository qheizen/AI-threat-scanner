from database.database_connector import db
from ..utils.tools import sanitize_sql_string
from ..utils import logger

_logger = logger.get_module_logger("TreatTypeMapper")


class ThreatType:

    def __init__(self, id: int = -1, threat_name: str = '', threat_description: str = '', 
                 threat_prototype: int = 0, created_by: int = 0):
        self.id = id
        self.threat_name = threat_name
        self.threat_description = threat_description
        self.threat_prototype = threat_prototype
        self.created_by = created_by

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatType":
        return cls(
            id=data.get("id", -1),
            threat_name=data.get("threatName", ""),
            threat_description=data.get("threatDescription", ""),
            threat_prototype=data.get("threatPrototype", 0),
            created_by=data.get("createdBy", 0),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "threatName": self.threat_name,
            "threatDescription": self.threat_description,
            "threatPrototype": self.threat_prototype,
            "createdBy": self.created_by,
        }


class ThreatTypeMapper:

    @staticmethod
    def get_threat_with_name(name: str) -> ThreatType:
        sanitized_name = sanitize_sql_string(name)
        if answer := db.search_db(
            "SELECT * FROM ThreatTypes WHERE threatName = '%s'" % sanitized_name
        ):
            threat_type = ThreatType.from_dict(answer[0])
            return threat_type

    @staticmethod
    def get_threat_types_from_user_id(id: int) -> list[ThreatType]:
        if answer := db.search_db(
            "SELECT * FROM ThreatTypes WHERE createdBy = %d" % id
        ):
            return [ThreatType.from_dict(row) for row in answer]

    @staticmethod
    def get_all() -> list[ThreatType]:
        if answer := db.search_db("SELECT * FROM ThreatTypes"):
            return [ThreatType.from_dict(row) for row in answer]

    @staticmethod
    def delete_user_with_id(id: int):
        db.write_db("DELETE FROM ThreatTypes WHERE id = %d" % id)

    @staticmethod
    def delete_user_with_name(name: int):
        sanitized_name = sanitize_sql_string(name)
        db.write_db("DELETE FROM ThreatTypes WHERE threatName = '%s'" % sanitized_name)

    @staticmethod
    def create(type: ThreatType) -> bool:
        if isinstance(type, dict):
            type = ThreatType.from_dict(type)

        if ThreatTypeMapper.get_threat_with_name(type.threat_name):
            _logger.error(f"Record {type.threat_name} already exists!")
            return False

        sql_request = "INSERT INTO ThreatTypes (threatName, threatDescription, threatPrototype, createdBy) VALUES ('%s', '%s', %s, %s)"
        request = sql_request % (
            sanitize_sql_string(type.threat_name),
            sanitize_sql_string(type.threat_description),
            int(type.threat_prototype),
            int(type.created_by),
        )
        try:
            db.write_db(request)
            return ThreatTypeMapper.get_threat_with_name(type.threat_name)

        except Exception as e:
            _logger.error(f"SQLite Error: {e}")
            return False
