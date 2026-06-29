import logging
import time
import traceback

from rich.console import Console
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA
from impacket.nmb import NetBIOSTimeout

console = Console(highlight=False)


class SMBUtils:

    def __init__(
        self,
        host,
        logon_domain,
        username,
        password,
        lmhash,
        nthash,
        do_kerberos=False,
        aeskey=None,
    ):
        self.host = host
        self.logon_domain = logon_domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.aeskey = aeskey
        self.smbClient = None
        self.connect()

    def connect(self):
        try:
            self.smbClient = SMBConnection(self.host, self.host)
        except (Exception, NetBIOSTimeout, OSError) as e:
            logging.info(f"Error creating SMB connection : {e}")
            logging.debug(traceback.format_exc())
            return

        if self.do_kerberos is True:
            self.smbClient.kerberosLogin(
                self.username,
                self.password,
                self.logon_domain,
                self.lmhash,
                self.nthash,
                self.aeskey,
                self.host,
            )
        else:
            self.smbClient.login(
                self.username,
                self.password,
                self.logon_domain,
                self.lmhash,
                self.nthash,
            )

    def reconnect(self):
        """
        Performs a series of reconnection attempts
        """

        for i in range(1, 3):
            logging.info(f"Reconnection attempt {i}/3 to server.")

            # Renegotiate the session
            time.sleep(3)
            self.connect()
            return True

        return False

    def close(self):
        if self.smbClient:
            try:
                self.smbClient.close()
            finally:
                self.smbClient = None

    def list_path(self, share, subfolder):
        """
        Returns a list of paths for a given share/folder.
        """

        filelist = []
        try:
            # Get file list for the current folder
            filelist = self.smbClient.listPath(share, subfolder + "*")

        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                console.print(f"[red bold][-][/] Cannot list files in SYSVOL{subfolder.strip('*')}")
            elif "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                console.print(f"[red bold][-][/] The folder SYSVOL{subfolder} does not exist")
            elif "STATUS_STOPPED_ON_SYMLINK" in str(e):
                console.print(
                    f"[red bold][-][/] The folder SYSVOL{subfolder} is a symlink that cannot be followed. Skipping"
                )
            else:
                logging.info(e)
                logging.debug(traceback.format_exc())
                if self.reconnect():
                    filelist = self.list_path(share, subfolder)

        except NetBIOSTimeout as e:
            console.print(f"[red bold][-][/] Failed listing files in SYSVOL{subfolder}")
            logging.info(e)
            logging.debug(traceback.format_exc())
        return filelist

    def get_remote_file(self, share, path):
        """
        Checks if a path is readable in a SMB share.
        """

        try:
            return RemoteFile(self.smbClient, path, share)
        except SessionError:
            if self.reconnect():
                return self.get_remote_file(path)

    def read_chunk(self, remote_file):
        """
        Reads the next chunk of data from the provided remote file.
        If a `SessionError` is encountered, it retries up to 3 times by reconnecting the SMB connection.
        If the maximum number of retries is exhausted or an unexpected exception occurs, it returns an empty chunk.
        """

        chunk = ""
        retry = 3

        while retry > 0:
            retry -= 1
            try:
                chunk = remote_file.read(4096)
                break

            except SessionError:
                if self.smb_utils.reconnect():
                    remote_file.smbClient = self.smbClient
                    return self.read_chunk(remote_file)

            except Exception as e:
                logging.debug(e)
                break

        return chunk


class RemoteFile:
    def __init__(self, smbConnection, fileName, share, access=FILE_READ_DATA):
        self.smbClient = smbConnection
        self.fileName = fileName
        self.share = share
        self.access = access
        self.tid = self.smbClient.connectTree(share)
        self.fid = None
        self.currentOffset = 0

    def open_file(self):
        self.fid = self.smbClient.openFile(self.tid, self.fileName, desiredAccess=self.access)

    def seek(self, offset, whence):
        if whence == 0:
            self.currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data = self.smbClient.readFile(self.tid, self.fid, self.currentOffset, bytesToRead)
            self.currentOffset += len(data)
            return data
        return ""

    def close(self):
        if self.fid is not None:
            self.smbClient.closeFile(self.tid, self.fid)
            self.fid = None
