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
from functools import wraps

_logger = logger.get_module_logger("API")
app = Flask(__name__)


def catcher(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            traceback_msg = traceback.format_exc()
            _logger.error(f"Something at {func.__name__}\nExc: {e}\n{traceback_msg}")
            return jsonify({"MESSAGES": str(e), "STATUS": 500}), 500
    return wrapper


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
    ok = user_repository.UserRepository.autentification(request_data["login"], request_data["password"])
    auth = user_repository.UserRepository.authorization(request_data["login"])
    has_perm = False
    try:
        if isinstance(auth, (list, tuple)) and len(auth) > operation:
            has_perm = bool(auth[operation])
    except Exception:
        has_perm = False

    if not ok or not has_perm:
        _logger.error(f"Forbidden {has_perm} {ok}")
        return jsonify({"MESSAGES": f"Forbidden {has_perm} {ok}", "STATUS": 403}), 403
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

    search_args = request_data.get("data", {}) or {}

    result = handler(**search_args)
    response_data = _base_response()

    if isinstance(result, list):
        resp_list = []
        for item in result:
            if hasattr(item, "to_dict"):
                resp_list.append(item.to_dict())
            elif isinstance(item, dict):
                resp_list.append(item)
            else:
                resp_list.append({"value": item})
        response_data["RESP"] = resp_list
    else:
        if result is None:
            response_data["RESP"] = []
        else:
            if hasattr(result, "to_dict"):
                response_data["RESP"].append(result.to_dict())
            elif isinstance(result, dict):
                response_data["RESP"].append(result)
            else:
                response_data["RESP"].append({"value": result})
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

    data_to_create = request_data.get("data", []) or []

    response_data = _base_response()

    for data in data_to_create:
        res = handler(data)
        if hasattr(res, "to_dict"):
            response_data["RESP"].append(res.to_dict())
        elif isinstance(res, dict):
            response_data["RESP"].append(res)
        else:
            response_data["RESP"].append({"id": getattr(res, "id", None)})

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

    data_to_update: list[dict] = request_data.get("data", []) or []
    response_data = _base_response()

    for data in data_to_update:
        if "id" not in data:
            continue
        _id = data.pop("id")
        handler(_id, data)

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

    delete_args = request_data.get("data", {})

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
    
    response_data = _base_response()
    user = user_repository.UserRepository.search(login=request_data["login"])
    if isinstance(user, list):
        if user:
            u = user[0]
            response_data["RESP"].append(u.to_dict() if hasattr(u, "to_dict") else u)
    elif user:
        response_data["RESP"].append(user.to_dict() if hasattr(user, "to_dict") else user)
    else:
        return jsonify({"MESSAGES": "User not found", "STATUS": 403}), 403
    return jsonify(response_data), 200


@catcher
@app.route("/online", methods=["POST"])
def get_online() -> tuple:
    response_data = _base_response()
    return jsonify(response_data), 200


def start_server():
    _logger.info("armtek emulator - start")
    app.run(debug=False, host=const.HOST, port=const.PORT)
