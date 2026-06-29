import logging


class RAWParser:
    """
    Parse raw binary files
    """

    def printable(self, string):
        chars = [char for char in string if char not in "\r\n"]
        if not chars:
            return True

        printable = sum(c.isprintable() for c in chars)
        return printable / len(chars) >= 0.95

    def decode_raw_file(self, file):
        try:
            type = file.get("type")
            output = {type: {"file": file["relative_path"]}}

            content = None

            # UTF-8
            try:
                with open(file["full_path"], "r", encoding="utf-8") as f:
                    content = f.read()

            except UnicodeDecodeError as error_utf8:

                # UTF-16LE
                try:
                    with open(file["full_path"], "r", encoding="utf-16-le") as f:
                        raw = f.read().lstrip("\ufeff")

                    if self.printable(raw):
                        content = raw

                except UnicodeDecodeError as error_utf16le:

                    # Latin-1 (last resort)
                    with open(file["full_path"], "r", encoding="latin-1") as f:
                        raw = f.read()

                    if self.printable(raw):
                        content = raw
                    else:
                        logging.debug(
                            f"Could not decode file {file['full_path']} as latin-1, as utf-8: {error_utf8} and as utf-16le: {error_utf16le}"
                        )

        except FileNotFoundError as error:
            logging.debug(f"Executable file not found : {error}")

        if content:
            output[type].update({"content": content})
            return output

        return None
