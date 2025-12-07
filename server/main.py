import os
import api_service


def main() -> None:
    print("env", "API STARTED LISTENING")
    api_service.start_server()


if __name__ == "__main__":
    main()
