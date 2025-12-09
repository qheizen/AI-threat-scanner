from ..data_mappers.threat_type_mapper import ThreatType, ThreatTypeMapper
from ..utils import logger

_logger = logger.get_module_logger("ThreatTypeRepository")


class ThreatTypeRepository:

    @staticmethod
    def create(type_data: dict) -> ThreatType:
        if any(
            key not in type_data
            for key in ["threatName", "createdBy"]
        ):
            _logger.error(f"Record corrupted {type_data}")
            return None

        return ThreatTypeMapper.create(type_data)

    @staticmethod
    def search(id: int = None, user_id: int = None, name: str = None, threatName: str = None):
        if name:
            return ThreatTypeMapper.get_threat_with_name(name)
        elif user_id:
            return ThreatTypeMapper.get_threat_types_from_user_id(user_id)
        elif id:
            return ThreatTypeMapper.get_threat_types_from_id(id)
        elif threatName:
            return ThreatTypeMapper.get_threat_with_name(threatName)
        else:
            return ThreatTypeMapper.get_all()

    @staticmethod
    def delete(id: int = None, name: int = None):
        if name and ThreatTypeMapper.search(name=name):
            return ThreatTypeMapper.delete_threat_with_name(name)
        elif id:
            return ThreatTypeMapper.delete_threat_with_id(id)
        return False

    @staticmethod
    def update(id: int, data: dict) -> bool:
        if ThreatTypeMapper.search(id=id):
            return ThreatTypeMapper.update(id, data)

        _logger.error(f"No record with id {id}")
        return False
