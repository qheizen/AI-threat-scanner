from .ai_core.ai_model import *
from .ai_core.ai_embeddings import * 
from .api_connector import Client
from .utils import const
import traceback
from .utils import logger
from functools import wraps

_logger = logger.get_module_logger("API")

def catcher(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            traceback_msg = traceback.format_exc()
            _logger.error(
                f"Something at {func.__name__}\nExc: {e}\n{traceback_msg}")

            return False
    return wrapper


class ModelController:
    
    def __init__(self, model_dir: str, client: Client):
        self.model_dir = model_dir
        self.client = client

    @catcher
    def train_model_with_server(self) -> bool:
        embeddings = self.client.get_train_data()
        train_model_with_embeddings(
            embeddings, const.MODEL_DIR, epochs=const.EPOCHS)
        _logger.info(f"Train data was loaded!")
        return True

    @catcher
    def train_model_with_file(self, file_path) -> bool:
        trained = train_model_with_list(file_path, const.MODEL_DIR, epochs=const.EPOCHS)
        self.client.create_new_threatfiles(trained)
        _logger.info(f"Train data was loaded!")
        return True

    @catcher
    def predict_with_list(self, file_path: str):
        file_path = file_path.strip()
        if not os.path.isdir(file_path):
            return False

        try:
            files = [f for f in os.listdir(file_path) if os.path.isfile(
                os.path.join(file_path, f))]
        except Exception as e:
            return False

        results = []
        for fname in files:
            full_path = os.path.join(file_path, fname)
            result = predict_file_with_path(full_path, const.MODEL_DIR)
            results.append(result)

        self.client.create_new_threatfiles(results)
        _logger.info(f"Train data was loaded!")
        return results
    
    @catcher
    def predict_single_file(self, file_path: str):
        result = predict_file_with_path(file_path, const.MODEL_DIR)
        self.client.create_new_threatfiles([result])
        _logger.info(f"Train data was loaded!")
        return [result]
    
    

