import sqlite3

from database.utils import const
from database.utils import logger

_logger = logger.get_module_logger("UTILS")


class DBConnector:

    def __init__(self, db_path: str):
        self.__db_path = db_path if db_path else const.DB_PATH

    def write_db(self, query: str):
        """
            Осуществляет запись в базу данных по запросу query
            in: query: str запрос SQL к базе данных
        """
        if not query.strip():
            _logger.error("SQL query cannot be empty")

        with sqlite3.connect(self.__db_path) as connection:
            _logger.debug(f"Write query: {query}")
            cursor = connection.cursor()
            cursor.execute(query)
            connection.commit()

    def search_db(self, query: str):
        """
            Осуществляет поиск и чтение данных из базы по запросу query
            in: query: str запрос SQL к базе данных
            out: list[dict]
        """
        if not query.strip():
            _logger.error("SQL query cannot be empty")

        with sqlite3.connect(self.__db_path) as connection:
            _logger.debug(f"Search query: {query}")
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()

            answer = cursor.execute(query).fetchall()
            answer_dict = [dict(row) for row in answer]
            return answer_dict
