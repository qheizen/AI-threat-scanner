from ..data_mappers.file_type_mapper import FileType, FileTypeMapper
from ..utils import logger

_logger = logger.get_module_logger("FileTypeRepository")


class FileTypeRepository:

    @staticmethod
    def search(id: int = None, name: str = None) -> FileType:
        if name:
            return FileTypeMapper.get_file_type_with_name(name)
        elif id:
            return FileTypeMapper.get_file_types_from_user_id(id)
        else:
            return FileTypeMapper.get_all()

    @staticmethod
    def create(type_data: dict) -> FileType:
        if any(key not in type_data for key in ["name", "extension"]):
            _logger.error(f"Record corrupted {type_data}")
            return None
        return FileTypeMapper.create(type_data)

    @staticmethod
    def delete(id: int = None, name: str = None) -> bool:
        if name and FileTypeRepository.search(name=name):
            return FileTypeRepository.delete_file_type_with_name(name)
        elif id:
            return FileTypeRepository.delete_file_type_with_id(id)
        return False

    @staticmethod
    def update(id: int, data: dict) -> bool:
        if FileTypeRepository.search(id=id):
            return FileTypeMapper.update(id, data)

        _logger.error(f"No record with id {id}")
        return False
