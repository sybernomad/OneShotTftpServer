from errno import EINTR
from tftpy import TftpException, TftpTimeout
from tftpy.TftpContexts import TftpContextServer
from tftpy.TftpPacketFactory import TftpPacketFactory
from tftpy.TftpShared import DEF_TFTP_PORT, DEF_TIMEOUT_RETRIES, MAX_BLKSIZE, SOCK_TIMEOUT

import logging
import select
import socket
import tftpy
import time

log = logging.getLogger("tftpy.TftpServer")


class OneShotTftpServer(tftpy.TftpServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def listen(
        self,
        listenip="",
        listenport=DEF_TFTP_PORT,
        timeout=SOCK_TIMEOUT,
        retries=DEF_TIMEOUT_RETRIES,
    ):
        """Start a server listening on the supplied interface and port. This
        defaults to INADDR_ANY (all interfaces) and UDP port 69. You can also
        supply a different socket timeout value, if desired."""
        tftp_factory = TftpPacketFactory()  # noqa

        if not listenip:
            listenip = "0.0.0.0"
        log.info("Server requested on ip %s, port %s" % (listenip, listenport))
        try:
            # FIXME - sockets should be non-blocking
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((listenip, listenport))
            _, self.listenport = self.sock.getsockname()
        except socket.error as err:
            # Reraise it for now.
            raise err

        self.is_running.set()

        log.debug("Starting receive loop...")
        while True:
            log.debug("shutdown_immediately is %s" % self.shutdown_immediately)
            log.debug("shutdown_gracefully is %s" % self.shutdown_gracefully)
            if self.shutdown_immediately:
                log.warning("Shutting down now. Session count: %d" % len(self.sessions))
                self.sock.close()
                for key in self.sessions:
                    self.sessions[key].end()
                self.sessions = []
                break

            elif self.shutdown_gracefully:
                if not self.sessions:
                    log.warning("In graceful shutdown mode and all " "sessions complete.")
                    self.sock.close()
                    break

            # Build the inputlist array of sockets to select() on.
            inputlist = []
            inputlist.append(self.sock)
            for key in self.sessions:
                inputlist.append(self.sessions[key].sock)

            # Block until some socket has input on it.
            log.debug("Performing select on this inputlist: %s", inputlist)
            try:
                readyinput, readyoutput, readyspecial = select.select(inputlist, [], [], timeout)
            except select.error as err:
                if err[0] == EINTR:
                    # Interrupted system call
                    log.debug("Interrupted syscall, retrying")
                    continue
                else:
                    raise

            deletion_list = []

            # Handle the available data, if any. Maybe we timed-out.
            for readysock in readyinput:
                # Is the traffic on the main server socket? ie. new session?
                if readysock == self.sock:
                    log.debug("Data ready on our main socket")
                    buffer, (raddress, rport) = self.sock.recvfrom(MAX_BLKSIZE)

                    log.debug("Read %d bytes", len(buffer))

                    if self.shutdown_gracefully:
                        log.warning("Discarding data on main port, " "in graceful shutdown mode")
                        continue

                    # Forge a session key based on the client's IP and port,
                    # which should safely work through NAT.
                    key = "%s:%s" % (raddress, rport)

                    if not key in self.sessions:  # noqa
                        log.debug("Creating new server context for " "session key = %s" % key)
                        self.sessions[key] = TftpContextServer(
                            raddress,
                            rport,
                            timeout,
                            self.root,
                            self.dyn_file_func,
                            self.upload_open,
                            retries=retries,
                        )
                        try:
                            self.sessions[key].start(buffer)
                        except TftpException as err:
                            deletion_list.append(key)
                            log.error("Fatal exception thrown from " "session %s: %s" % (key, str(err)))
                    else:
                        log.warning("received traffic on main socket for " "existing session??")
                    log.debug("Currently handling these sessions:")
                    for session_key, session in list(self.sessions.items()):
                        log.debug("    %s" % session)

                else:
                    # Must find the owner of this traffic.
                    for key in self.sessions:
                        if readysock == self.sessions[key].sock:
                            log.debug("Matched input to session key %s" % key)
                            try:
                                self.sessions[key].cycle()
                                if self.sessions[key].state is None:
                                    log.info("Successful transfer.")
                                    deletion_list.append(key)
                                    self.stop()
                            except TftpException as err:
                                deletion_list.append(key)
                                log.error("Fatal exception thrown from " "session %s: %s" % (key, str(err)))
                            # Break out of for loop since we found the correct
                            # session.
                            break
                    else:
                        log.error("Can't find the owner for this packet. " "Discarding.")

            log.debug("Looping on all sessions to check for timeouts")
            now = time.time()
            for key in self.sessions:
                try:
                    self.sessions[key].checkTimeout(now)
                except TftpTimeout as err:
                    log.error(str(err))
                    self.sessions[key].retry_count += 1
                    if self.sessions[key].retry_count >= self.sessions[key].retries:
                        log.debug("hit max retries on %s, giving up" % self.sessions[key])
                        deletion_list.append(key)
                    else:
                        log.debug("resending on session %s" % self.sessions[key])
                        self.sessions[key].state.resendLast()

            log.debug("Iterating deletion list.")
            for key in deletion_list:
                log.debug("")
                log.debug("Session %s complete" % key)
                if key in self.sessions:
                    log.debug("Gathering up metrics from session before deleting")
                    self.sessions[key].end()
                    metrics = self.sessions[key].metrics
                    if metrics.duration == 0:
                        log.debug("Duration too short, rate undetermined")
                    else:
                        log.debug("Transferred %d bytes in %.2f seconds" % (metrics.bytes, metrics.duration))
                        log.debug("Average rate: %.2f kbps" % metrics.kbps)
                    log.debug("%.2f bytes in resent data" % metrics.resent_bytes)
                    log.debug("%d duplicate packets" % metrics.dupcount)
                    log.debug("Deleting session %s" % key)
                    del self.sessions[key]
                    log.debug("Session list is now %s" % self.sessions)
                else:
                    log.warning("Strange, session %s is not on the deletion list" % key)

        self.is_running.clear()

        log.debug("server returning from while loop")
        self.shutdown_gracefully = self.shutdown_immediately = False
