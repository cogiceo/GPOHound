import csv
from gpohound.utils.utils import load_yaml_config


class CSVParser:
    """Parse the audit policy file"""

    def __init__(self, config="config.gpo_files_structure.csv") -> None:
        self.config = load_yaml_config(config)

    def parse(self, file_path):
        """
        Parse the audit.csv file
        """

        # Verify if the files needs to be included in the output
        if "include" in self.config["Audit"]:
            extracted_data = []

            # Convert the CSV table to a directory
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                next(reader)

                # Filter column that are not in the config
                for line in reader:
                    extracted_data.append({key: line[key] for key in self.config["Audit"]["attributes"] if key in line})

            return {"audit.csv": extracted_data}

        return None
