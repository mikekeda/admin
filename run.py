import grp
import logging
import os
import socket

from sanic.log import logger

from admin.views import app


def log_to_stderr_with_timestamps() -> None:
    """Give library log records and Python warnings the timestamped format Sanic uses for its own."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S %z"))
    handler.addFilter(lambda record: not record.name.startswith("sanic."))  # Sanic's loggers have their own handlers.
    logging.getLogger().addHandler(handler)
    logging.captureWarnings(True)


# Module level, not under __main__: Sanic's worker process re-imports this file without running that block.
log_to_stderr_with_timestamps()

if __name__ == "__main__":
    if app.config["DEBUG"]:
        app.run(host="127.0.0.1", port=8000, debug=True)
    else:
        # Remove old socket (is any).
        try:
            os.unlink(app.config["SOCKET_FILE"])
        except FileNotFoundError as e:
            logger.info(f"No old socket file found: {e}")

        # Create socket and run app.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(app.config["SOCKET_FILE"])

                os.chmod(app.config["SOCKET_FILE"], 0o775)
                os.chown(app.config["SOCKET_FILE"], -1, grp.getgrnam("www-data").gr_gid)

                app.run(sock=sock, access_log=False)
            except OSError as e:
                logger.warning(e)
