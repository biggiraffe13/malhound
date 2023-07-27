# malhound - Null bytes(bloat) removal and IOC extraction tool for PE files

> This Is A Simple Application To Debloat/Remove Null-Bytes In Executables and extract IOCs from PE files Using
> Python
![image](https://github.com/biggiraffe13/malhound/assets/117535720/e108b249-be92-4213-ae8c-5bd8346e318b)

---

### Core Features

* Show Executable File Information Such As:
    * File Type (Supports Mainly `PE` Files)
    * File Name
    * File Size
    * `MD5` Hash
    * Packed IOCs
    * Compression Ratio
    * Number of Sections in the `PE`
    * Display Each Section With Information Like (Name, Size, and Compression Ratio) for Each Section

* Modify the `PE` File by:
    * Remove The Excess Null-Bytes

#### Main Interface
![image](https://github.com/biggiraffe13/malhound/assets/117535720/c83c55dd-8a0f-42a0-b4b2-fd687ff681b8)


### Running The App

* #### Running The GUI / CLI Version

Install The App Package Using `pip` by Downloading the `wheel` Package Include Then Run:

```commandline
pip install MalHound-0.0.1-py3-none-any.whl
```

* To Access The **CLI** Run:

```commandline
MalHound input_file_path
```

* To Access The **GUI** Run:

```commandline
MalHound-gui
```

* #### Running GUI Via The Executable

You Can Run The App Using The `.EXE` Provided In The Releases Section

* #### Running Locally Via [GitHub](https://github.com/biggiraffe13/malhound)

You Can Run This App Locally By Following These Steps:

1. Clone/Download 
2. Open Cmd/Terminal And `cd` Into The Project Root Directory
3. Execute ```pip install -e .```

Now To Run The Application, Execute ```python -m MalHound``` In `src/MalHound` Directory

### Supported Versions

The App Was Tested With The Following Versions Of Python

| Version | Windows            | Linux              | MacOS              |
|---------|--------------------|--------------------|--------------------|
| 3.11    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| 3.10    | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Credits

This App Was Inspired By [Debloat](https://github.com/Squiblydoo/debloat) App Created By `Squiblydoo` As I Have Used
His `processor.py` File.
