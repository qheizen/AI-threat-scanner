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
            _logger.error(f"Something at {func.__name__}\nExc: {e}\n{traceback_msg}")
            return jsonify({"MESSAGES": str(e), "STATUS": 500}), 500

    return wrapper


@catcher
@app.route("/search", methods=["POST"])
def search() -> tuple:
    handlers = {
        "FileType": file_type_repository.FileTypeRepository.search,
        "ThreatType": threat_type_repository.ThreatTypeRepository.search,
        "ThreateningFiles": threatening_files_repository.ThreateningFileRepository.search,
    }

    request_data: dict = request.get_json()
    _logger.info(f"Search start, input: {request_data}")

    if any(key not in request_data for key in ["login", "password", "table"]):
        return jsonify({"MESSAGES": f"Invalid input data: {request_data}"}), 400

    if (
        not user_repository.UserRepository.autentification(
            request_data["login"], request_data["password"]
        )
        or user_repository.UserRepository.authorization(request_data["login"])[1]
        == False
    ):
        return jsonify({"MESSAGES": "Forbidden", "STATUS": 403}), 403

    response_data = {"STATUS": 200, "MESSAGES": [], "RESP": []}
    table = request_data["table"]
    if table not in handlers:
        return jsonify({"MESSAGES": f"Unknown table: {table}", "STATUS": 400}), 400
    handler = handlers[table]

    search_args = {
        k: v for k, v in request_data.items() if k not in ["login", "password", "table"]
    }

    result = handler(**search_args)
    if isinstance(result, list):
        response_data["RESP"] = result
    else:
        response_data["RESP"].append(result)
    return jsonify(response_data), 200


@app.route("/create", methods=["POST"])
def create() -> tuple:
    handlers = {
        "FileType": file_type_repository.FileTypeRepository.create,
        "ThreatType": threat_type_repository.ThreatTypeRepository.create,
        "ThreateningFiles": threatening_files_repository.ThreateningFileRepository.create,
    }

    request_data: dict = request.get_json()
    _logger.info(f"Create start, input: {request_data}")
    if any(key not in request_data for key in ["login", "password", "table"]):
        return jsonify({"MESSAGES": f"Invalid input data: {request_data}"}), 400

    if (
        not user_repository.UserRepository.autentification(
            request_data["login"], request_data["password"]
        )
        or user_repository.UserRepository.authorization(request_data["login"])[1]
        == False
    ):
        return jsonify({"MESSAGES": "Forbidden", "STATUS": 403}), 403

    response_data = {"STATUS": 200, "MESSAGES": [], "RESP": []}
    data_to_create = request_data["data"]
    table = request_data["table"]
    if table not in handlers:
        return jsonify({"MESSAGES": f"Unknown table: {table}", "STATUS": 400}), 400

    handler = handlers[table]
    for data in data_to_create:
        response_data["RESP"].append(handler(data))

    return jsonify(response_data), 200


@catcher
@app.route("/update", methods=["POST"])
def update() -> tuple:
    handlers = {
        "FileType": file_type_repository.FileTypeRepository.update,
        "ThreatType": threat_type_repository.ThreatTypeRepository.update,
        "ThreateningFiles": threatening_files_repository.ThreateningFileRepository.update,
    }
    request_data: dict = request.get_json()
    _logger.info(f"Update start, input: {request_data}")
    if any(key not in request_data for key in ["login", "password", "table"]):
        return jsonify({"MESSAGES": f"Invalid input data: {request_data}"}), 400

    if (
        not user_repository.UserRepository.autentification(
            request_data["login"], request_data["password"]
        )
        or user_repository.UserRepository.authorization(request_data["login"])[1]
        == False
    ):
        return jsonify({"MESSAGES": "Forbidden", "STATUS": 403}), 403

    response_data = {"STATUS": 200, "MESSAGES": [], "RESP": []}
    data_to_create = request_data["data"]
    table = request_data["table"]
    if table not in handlers:
        return jsonify({"MESSAGES": f"Unknown table: {table}", "STATUS": 400}), 400

    handler = handlers[table]
    for data in data_to_create:
        handler(data)

    return jsonify(response_data), 200


@catcher
@app.route("/delete", methods=["POST"])
def delete() -> tuple:
    handlers = {
        "FileType": file_type_repository.FileTypeRepository.delete,
        "ThreatType": threat_type_repository.ThreatTypeRepository.delete,
        "ThreateningFiles": threatening_files_repository.ThreateningFileRepository.delete,
    }

    request_data: dict = request.get_json()
    _logger.info(f"Delete start, input: {request_data}")

    if any(key not in request_data for key in ["login", "password", "table"]):
        return jsonify({"MESSAGES": f"Invalid input data: {request_data}"}), 400

    if (
        not user_repository.UserRepository.autentification(
            request_data["login"], request_data["password"]
        )
        or user_repository.UserRepository.authorization(request_data["login"])[1]
        == False
    ):
        return jsonify({"MESSAGES": "Forbidden", "STATUS": 403}), 403

    response_data = {"STATUS": 200, "MESSAGES": [], "RESP": []}
    table = request_data["table"]
    if table not in handlers:
        return jsonify({"MESSAGES": f"Unknown table: {table}", "STATUS": 400}), 400
    handler = handlers[table]

    search_args = {
        k: v for k, v in request_data.items() if k not in ["login", "password", "table"]
    }

    handler(**search_args)
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
    response_data = {"STATUS": 200, "MESSAGES": [], "RESP": []}
    user = user_repository.UserRepository.create(request_data)
    response_data["RESP"].append(user)
    return jsonify(response_data), 200


def start_server():
    _logger.info("armtek emulator - start")
    app.run(debug=False, host=const.HOST, port=const.PORT)
