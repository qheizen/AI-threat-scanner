from .api_service import start_server


def main() -> None:
    print("env", "API STARTED LISTENING")
    start_server()


if __name__ == "__main__":
    main()
