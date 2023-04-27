from oneshot_tftp_server.server import OneShotTftpServer

import argparse
import logging
import sys
import tftpy

log = logging.getLogger("tftpy")
log.setLevel(logging.INFO)

# console handler
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
default_formatter = logging.Formatter("[%(asctime)s] %(message)s")
handler.setFormatter(default_formatter)
log.addHandler(handler)


def main():
    # create a new ArgumentParser object
    parser = argparse.ArgumentParser()

    # add command line arguments to the parser
    parser.add_argument(
        "-i",
        "--ip",
        type=str,
        help="ip address to bind to (default: 0.0.0.0)",
        default="0.0.0.0",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="port to bind to (default: 69)",
        default=69,
    )

    parser.add_argument("-r", "--root", type=str, help="path to serve from", required=True)
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Do not log unless it is critical",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="upgrade logging from info to debug",
    )

    # parse the command line arguments
    args = parser.parse_args()

    # configure logging based on the command line arguments
    if args.debug:
        log.setLevel(logging.DEBUG)
        debug_formatter = logging.Formatter("[%(asctime)s%(msecs)03d] %(levelname)s [%(name)s:%(lineno)s] %(message)s")
        handler.setFormatter(debug_formatter)
    elif args.quiet:
        log.setLevel(logging.WARN)

    # create a TFTP server instance and start listening
    server = OneShotTftpServer(args.root)
    try:
        server.listen(listenip=args.ip, listenport=args.port)
    except tftpy.TftpException as err:
        sys.stderr.write("%s\n" % str(err))
        sys.exit(1)
    except PermissionError as err:
        sys.stderr.write("Unable to use the specified ip or port: %s\n" % str(err))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
