import os
import socket

from sanic.log import logger

from admin.views import app

if __name__ == "__main__":
    if app.config['DEBUG']:
        app.run(host="0.0.0.0", port=8000, debug=True)
    else:
        # Remove old socket (is any).
        try:
            os.unlink(app.config['SOCKET_FILE'])
        except FileNotFoundError as e:
            logger.info(f"No old socket file found: {e}")

        # Create socket and run app.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(app.config['SOCKET_FILE'])
                app.run(sock=sock, access_log=False)
            except OSError as e:
                logger.warning(e)
