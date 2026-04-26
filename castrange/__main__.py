from castrange.app import create_app


def main():
    app = create_app()
    app.run(host="127.0.0.1", port=5002, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
