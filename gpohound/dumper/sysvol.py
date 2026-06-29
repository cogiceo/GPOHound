import re
import logging
import traceback

from pathlib import Path, PurePosixPath

from rich.console import Console

from gpohound.protocols.smb import SMBUtils

from impacket.smbconnection import SessionError

console = Console(highlight=False)


class SYSVOLDumper:
    """
    Class to dump the files in the SYSVOL share
    """

    def __init__(
        self,
        smb_utils: SMBUtils,
        include=None,
        exclude=None,
        max_file_size=None,
        gpos=False,
        analysis=False,
        output_folder="SYSVOLS",
    ):
        self.smb_utils = smb_utils

        self.include_filter = include.split(",") if include else []
        self.exclude_filter = exclude.split(",") if exclude else []

        self.max_file_size = max_file_size * 1000 * 1000 if max_file_size else None
        self.output_folder = output_folder

        if gpos:
            self.include_filter.extend([r".*?/[^/]+/Policies/\{[0-9A-Fa-f-]{36}\}.*"])
        elif analysis:
            self.include_filter.extend(
                [r".*/Groups.xml$", r".*/Registry.xml$", r".*/registry.pol$", r".*/GptTmpl.inf$"]
            )

    def exclude_path(self, path):
        return any(re.search(p, path, re.IGNORECASE) for p in self.exclude_filter)

    def include_file(self, path):
        if not self.include_filter:
            return True
        return any(re.search(p, path, re.IGNORECASE) for p in self.include_filter)

    def get_file_save_path(self, share, remote_file):
        """
        Processes the remote file path to extract the filename and the folder path where the file should be saved locally.
        Creates a PurePosixPath and replaces UNC parts, then cleans it of any path traversal
        """

        raw_path = PurePosixPath(share, remote_file.fileName.replace("\\", "/"))
        clean_parts = [p for p in raw_path.parts if p not in ("..", ".", "/")]
        resolved = Path(self.output_folder).joinpath(*clean_parts)
        return str(resolved.parent), resolved.name

    def save_file(self, share, remote_file):
        # Reset the remote_file to point to the beginning of the file.
        remote_file.seek(0, 0)

        folder, filename = self.get_file_save_path(share, remote_file)
        download_path = Path(folder) / filename

        # Create the subdirectory
        logging.info(f"Creating folder '{folder}'")
        Path(folder).mkdir(parents=True, exist_ok=True)

        try:
            with open(download_path, "wb") as fd:
                while True:
                    chunk = self.smb_utils.read_chunk(remote_file)
                    if not chunk:
                        break
                    fd.write(chunk)

        except Exception as e:
            console.print(f"[red bold][-][/] Error writing file {download_path}")
            logging.info(e)
            logging.info(traceback.format_exc())
            return

        # Check if the file is empty and should not be.
        if (
            download_path.stat().st_size == 0
            and hasattr(remote_file, "get_filesize")
            and remote_file.get_filesize() > 0
        ):
            download_path.unlink()
            console.print(f"[red bold][-][/] Unable to download file {remote_file.fileName}")

    def parse_file(self, share, file_path, file_size, file_modified_time):
        """
        Checks file attributes against various filters, then downloads it
        """

        # Check file size limits.
        if self.max_file_size and file_size > self.max_file_size:
            logging.info(f'The file "SYSVOL{file_path}" has been excluded (maximum size)')
            return

        # Check if the remote file is readable.
        remote_file = self.smb_utils.get_remote_file(share, file_path)
        if not remote_file:
            logging.info(f'Cannot read remote file "SYSVOL{file_path}".')
            return

        # Check if the file is already downloaded and up-to-date.
        file_dir, file_name = self.get_file_save_path(share, remote_file)
        download_path = Path(file_dir) / file_name
        if download_path.exists():
            stats = download_path.stat()
            if file_modified_time <= stats.st_mtime and stats.st_size == file_size:
                console.print(f"[yellow bold][+][/yellow bold] Up-to-date: '{download_path}'")
                return

        # Download file.
        try:
            remote_file.open_file()
            self.save_file(share, remote_file)
            remote_file.close()
        except SessionError as e:
            if "STATUS_SHARING_VIOLATION" in str(e):
                pass
            return
        except Exception as e:
            console.print(f"[red bold][-][/] Failed to download file SYSVOL{file_path}")
            logging.info(e)
            logging.debug(traceback.format_exc())
            return
        console.print(f"[green bold][+][/] Downloaded: '{download_path}'")

    def download(self, share="SYSVOL", folder="/"):
        """
        Dumps the SYSVOL share based on options
        """

        filelist = self.smb_utils.list_path(share, folder + "*")

        for result in filelist:
            next_filedir = result.get_longname()
            if next_filedir in [".", ".."]:
                continue
            next_fullpath = folder + next_filedir
            result_type = "folder" if result.is_directory() else "file"

            # Check file-dir exclusion filter.
            if self.exclude_path(next_fullpath.lower()):
                logging.info(f'The {result_type} "{next_fullpath}" has been excluded (exclusion filter)')
                continue

            if result_type == "folder":
                logging.debug(
                    f'Current folder: "{next_fullpath}"',
                )
                self.download(share, next_fullpath + "/")
            else:
                logging.info(f'Current file: "{next_fullpath}"')
                if self.include_file(next_fullpath.lower()):
                    file_size = result.get_filesize()
                    file_modified_time = result.get_mtime_epoch()
                    self.parse_file(share, next_fullpath, file_size, file_modified_time)
                else:
                    logging.info(f'The file "{next_fullpath}" has been excluded (inclusion filter)')
