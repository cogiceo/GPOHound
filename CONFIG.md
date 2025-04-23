# Configuration

All configuration files for the tool are located in the `config/` directory. These files are written in YAML format.

## Custom Configuration

You can override any default configuration by placing a file with the same name in your GPOHound user configuration directory.
This path is resolved automatically using [`platformdirs.user_config_dir`](https://pypi.org/project/platformdirs/) and is platform-specific.

On Linux, the configuration directory will be `~/.config/gpohound`.

> The configuration folder is created if it does not exist.

To create a custom config:
1. Copy the desired file from `config/` (e.g., `config/gpo_files_structure/xml/ScheduledTasks.yaml`).
2. Paste it into your user config folder (e.g., `~/.config/gpohound/`).
3. Modify it to suit your preferences.

## Structure

The `config/gpo_file_structures/` directory contains configuration files that specify the structure and display format for each type of GPO file. To exclude specific sections or attributes from being parsed, simply comment out the corresponding lines in the YAML configuration.

### Examples

#### Default configuration

```yaml
General:
  include: 
  attributes:
    - Version
    - displayName
```

#### Exclude a section

```yaml
General:
  #include: 
  attributes:
    - Version
    - displayName
```

#### Exclude an attribute

```yaml
General:
  include: 
  attributes:
    #- Version
    - displayName
```
> [!NOTE]
> For XML files, sections that are not defined in the structure will be included in the output by default. 