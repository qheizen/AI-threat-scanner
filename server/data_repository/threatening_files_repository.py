from ..data_mappers.threatening_files_mapper import ThreateningFile, ThreateningFileMapper
from ..utils import logger

_logger = logger.get_module_logger("ThreateningFileRepository")


class ThreateningFileRepository:

    @staticmethod
    def create(file_data: dict) -> ThreateningFile:
        if any(
            key not in file_data
            for key in ["fileName", "sha256", "fileEmbedding"]
        ):
            _logger.error(f"Record corrupted {file_data}")
            return None

        return ThreateningFileMapper.create(file_data)

    @staticmethod
    def search(id: int = None, approve_state: str = None, sha256: str = None, user_id: int = None, threat_type: int = None):
        if id:
            return ThreateningFileMapper.get_file_with_id(id)
        elif approve_state:
            return ThreateningFileMapper.get_files_from_approve_state(approve_state)
        elif sha256:
            return ThreateningFileMapper.get_file_with_sha256(sha256)
        elif user_id:
            return ThreateningFileMapper.get_files_from_user_id(user_id)
        elif threat_type:
            return ThreateningFileMapper.get_files_from_threat_type_id(threat_type)
        else:
            return ThreateningFileMapper.get_all()

    @staticmethod
    def delete(id: int = None, sha256: str = None):
        if sha256 and ThreateningFileMapper.search(sha256=sha256):
            return ThreateningFileMapper.delete_file_with_sha256(sha256)
        elif id:
            return ThreateningFileMapper.delete_file_with_id(id)
        return False

    @staticmethod
    def approve(id):
        if file := ThreateningFileRepository.search(id=id):
            ThreateningFileMapper.update_file_status(file.id, "approved")

    @staticmethod
    def unapprove(id):
        if file := ThreateningFileRepository.search(id=id):
            ThreateningFileMapper.update_file_status(file.id, "unnaproved")

    @staticmethod
    def update(id: int, data: dict) -> bool:
        if ThreateningFileMapper.search(id=id):
            return ThreateningFileMapper.update(id, data)

        _logger.error(f"No record with id {id}")
        return False
