from store import get_es_client


def main() -> int:
    try:
        info = get_es_client().info()
        print("Connected!", info)
        return 0
    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
