# MalHound (null-bytes removal tool for executables)

> This is a simple file to hold the description of each folder in the package and what it does.

1. setup.py, setup.cfg, pyproject.toml

    * All three of these files are responsible for the configuration of the build system (in this app we
      use `setuptools`)
      used to build the app python package, and they hold some metadata about the app needed when published like the
      author
      name and email,license and README files, some package classifiers and keywords, package version,package
      dependencies, which python version it shall run on, and it also tells the build system where
      to find the package data and files (which is inside the `src` folder).
    * `pyproject.toml` contains some important info like the app main repo link on GitHub in the `[project.urls]`
      section
      and the scripts needed to run the app
      GUI/CLI version contained in `[project.scripts]` section.

2. requirements.txt

    * That file holds the app dependencies and their specific version, so it can be read and installed by your IDE of
      choice like `VSCode`
      or `PyCharm`,
      in **jupyter** you can use the command ``` pip install -r /path/to/requirements.txt ``` to install all required
      libraries for the app to run.

3. README.md
    * This file just contains a description of the project that can be displayed on the GitHub repo and what it does and
      how to run it.

4. MANIFEST.in
    * This file is used to tell the building system to include all the files in the `icons` directory in the package
      data.

5. LICENSE
    * This just holds the license info for the app.

6. CHANGELOG.md
    * This file contains all the changes and bug fixes across various versions of the app.
    * Each app version should indicate its changes, additions and fixes applied to it.
    * It should follow semantic versioning rules.

7. .gitignore
    * It just holds the files and folders that will not be tracked by git.
    * This includes unnecessary files and caching files used by the build system.

-------------------------

1. src
    * This holds the main source code for the app plus the icons data folder needed for the GUI.
    * Inside it shall be the main directory of the package, and it shall have the same name as the package name.
        * __init__.py : It's used to declare the app as a python module it also has the variable referencing the `icons`
          data folder, so it can be used as a path to the icons' data.
        * interface.py : The main entry point for the app GUI interface as it holds the main code.
        * main.py : It contains the code for the CLI version of the app.
        * processor.py : It contains the `.exe` file analyzing code.
2. dist
    * It contains the pre-build app package that is ready to be installed with `pip` or can be distributed using `PyPi`
      hosting site.
        * MalHound-0.0.1.tar.gz : This is the source code package.
        * MalHound-0.0.1-py3-none-any.whl : This is the pre-build app package that is ready to be installed.
    * To install the app package on `Windows/Linux` you can use this
      command ```pip install MalHound-0.0.1-py3-none-any.whl```