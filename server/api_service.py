from flask import Flask, jsonify, request
from .data_repository import (
    user_repository,
    file_type_repository,
    threat_type_repository,
    threatening_files_repository,
)
from .data_mappers import *
import traceback
from .utils import logger
from .utils import const

_logger = logger.get_module_logger("API")
app = Flask(__name__)


def catcher(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            traceback_msg = traceback.format_exc()
            _logger.error(
                f"Something at {func.__name__}\nExc: {e}\n{traceback_msg}")
            return jsonify({"MESSAGES": str(e), "STATUS": 500}), 500

    return wrapper


# Универсальный маппинг таблица -> репозиторий
TABLE_HANDLERS = {
    "FileType": {
        "search": file_type_repository.FileTypeRepository.search,
        "create": file_type_repository.FileTypeRepository.create,
        "update": file_type_repository.FileTypeRepository.update,
        "delete": file_type_repository.FileTypeRepository.delete,
    },
    "ThreatType": {
        "search": threat_type_repository.ThreatTypeRepository.search,
        "create": threat_type_repository.ThreatTypeRepository.create,
        "update": threat_type_repository.ThreatTypeRepository.update,
        "delete": threat_type_repository.ThreatTypeRepository.delete,
    },
    "ThreateningFiles": {
        "search": threatening_files_repository.ThreateningFileRepository.search,
        "create": threatening_files_repository.ThreateningFileRepository.create,
        "update": threatening_files_repository.ThreateningFileRepository.update,
        "delete": threatening_files_repository.ThreateningFileRepository.delete,
    },
}


def _validate_base_request(request_data: dict):
    """Проверка наличия обязательных полей login/password/table."""
    if any(key not in request_data for key in ["login", "password", "table"]):
        return jsonify({"MESSAGES": f"Invalid input data: {request_data}"}), 400
    return None


def _check_auth(request_data: dict, operation: int = 0):
    """Аутентификация и авторизация пользователя."""
    if (
        not user_repository.UserRepository.autentification(
            request_data["login"], request_data["password"]
        )
        or user_repository.UserRepository.authorization(request_data["login"])[operation]
        is False
    ):
        return jsonify({"MESSAGES": "Forbidden", "STATUS": 403}), 403
    return None


def _get_table_handler(table: str, operation: str):
    """Получение обработчика по названию таблицы и операции."""
    table_info = TABLE_HANDLERS.get(table)
    if not table_info:
        return (
            jsonify({"MESSAGES": f"Unknown table: {table}", "STATUS": 400}),
            400,
            None,
        )
    handler = table_info.get(operation)
    if not handler:
        return (
            jsonify(
                {
                    "MESSAGES": f"Unknown operation '{operation}' for table: {table}",
                    "STATUS": 400,
                }
            ),
            400,
            None,
        )
    return None, None, handler


def _base_response():
    return {"STATUS": 200, "MESSAGES": [], "RESP": []}


@catcher
@app.route("/search", methods=["POST"])
def search() -> tuple:
    request_data: dict = request.get_json()
    _logger.info(f"Search start, input: {request_data}")

    # Валидируем базовые поля
    error = _validate_base_request(request_data)
    if error:
        return error

    error = _check_auth(request_data, 1)
    if error:
        return error

    table = request_data["table"]
    err_resp, status, handler = _get_table_handler(table, "search")
    if handler is None:
        return err_resp, status

    search_args = {
        k: v for k, v in request_data.items() if k not in ["login", "password", "table"]
    }

    result = handler(**search_args)
    response_data = _base_response()
    if isinstance(result, list):
        response_data["RESP"] = [user.to_dict() for user in result]
    else:
        response_data["RESP"].append(result.to_dict())

    return jsonify(response_data), 200


@catcher
@app.route("/create", methods=["POST"])
def create() -> tuple:
    request_data: dict = request.get_json()
    _logger.info(f"Create start, input: {request_data}")

    error = _validate_base_request(request_data)
    if error:
        return error

    error = _check_auth(request_data, 0)
    if error:
        return error

    table = request_data["table"]
    err_resp, status, handler = _get_table_handler(table, "create")
    if handler is None:
        return err_resp, status

    data_to_create = request_data.get("data", [])
    
    response_data = _base_response()

    for data in data_to_create:
        response_data["RESP"].append(handler(data).to_dict())

    return jsonify(response_data), 200


@catcher
@app.route("/update", methods=["POST"])
def update() -> tuple:
    request_data: dict = request.get_json()
    _logger.info(f"Update start, input: {request_data}")

    error = _validate_base_request(request_data)
    if error:
        return error

    error = _check_auth(request_data, 2)
    if error:
        return error

    table = request_data["table"]
    err_resp, status, handler = _get_table_handler(table, "update")
    if handler is None:
        return err_resp, status

    data_to_update = request_data.get("data", [])
    response_data = _base_response()

    for data in data_to_update:
        handler(data)

    return jsonify(response_data), 200


@catcher
@app.route("/delete", methods=["POST"])
def delete() -> tuple:
    request_data: dict = request.get_json()
    _logger.info(f"Delete start, input: {request_data}")

    error = _validate_base_request(request_data)
    if error:
        return error

    error = _check_auth(request_data, 3)
    if error:
        return error

    table = request_data["table"]
    err_resp, status, handler = _get_table_handler(table, "delete")
    if handler is None:
        return err_resp, status

    delete_args = {
        k: v for k, v in request_data.items() if k not in ["login", "password", "table"]
    }

    handler(**delete_args)
    response_data = _base_response()
    return jsonify(response_data), 200


@catcher
@app.route("/register", methods=["POST"])
def register_user() -> tuple:
    request_data: dict = request.get_json()
    _logger.info(f"New User start, input: {request_data}")

    request_data |= {
        "can_create": 0,
        "can_update": 0,
        "can_delete": 0,
        "can_read": 0,
        "registered": 0,
    }

    response_data = _base_response()
    user = user_repository.UserRepository.create(request_data)
    response_data["RESP"].append(user.to_dict())
    return jsonify(response_data), 200


@catcher
@app.route("/getuserid", methods=["POST"])
def get_user_id() -> tuple:
    request_data: dict = request.get_json()
    _logger.info(f"User search start, input: {request_data}")

    error = _check_auth(request_data, 1)
    if error:
        return error

    response_data = _base_response()
    user = user_repository.UserRepository.search(login=request_data["login"])
    response_data["RESP"].append(user.to_dict())
    return jsonify(response_data), 200


def start_server():
    _logger.info("armtek emulator - start")
    app.run(debug=False, host=const.HOST, port=const.PORT)
