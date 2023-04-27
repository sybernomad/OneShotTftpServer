# OneShot TFTP Server

`OneShotTftpServer` is a Python library that provides a modified implementation of the `tftpy.TftpServer` class. This modified version shuts down the server once a file has been downloaded, making it suitable for use in situations where only a single file needs to be served.

## Usage

To use `OneShotTftpServer`, simply import the class and create a new instance with the desired configuration options. For example, to serve a directory named `/tmp/dir` from the current directory on port 69, you can use the following code:

```python
from oneshot_tftp_server.server import OneShotTftpServer

server = OneShotTftpServer('/tmp/dir')
server = OneShotTftpServer(args.root)
try:
    server.listen(listenip=args.ip, listenport=args.port)
except (tftpy.TftpException, OSError) as err:
    sys.stderr.write("%s\n" % str(err))
    sys.exit(1)
except PermissionError as err:
    sys.stderr.write("Unable to use the specified ip or port: %s\n" % str(err))        
    sys.exit(1)
except KeyboardInterrupt:
    sys.exit(1)
```