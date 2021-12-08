# CSDS 344 / 444: Final course project

## Cryptographic Tools and User Interface:

- Alex Rambasek
- Cameron Byrne
- Kris Zhao
- Phan Trinh Ha
- Stamatis Papadopoulos

## Requirements:

Throughout the project, there were a couple python tools necessary (that were not cryptographic libraries). These can be installed from the requirements text file:
```
pip install requirements.txt
```
OR
```
python -m pip install requirements.txt
```

## Directories:

Through the developement of the project, there were three primary directories work was done in.

### Algorithms:

The algoirthms directory was the working directory for each of us to develop the algorithmic backends. This meant creating test scripts for the algorithms, as well as callable functions that could "bundle" all of the functionality together as well as test command line interfaces.

### Configuration:

The configuration was a sample method for directing and consolidating each algorithm into a single UI with pausing and printout functionality. With the unique structure of Django, this method had to be abandoned for other connectors.

### Ui

The UI folder was the final wrap up directory for the project. This included all of the django files for displaying web pages, uploading files, and running each algorithm. As such, all algorithms from the Algorithm directory were ported into this folder.

This is to say that with only the UI folder, the completed project could be demoed.

## Running the demo:
With the requirements installed, you should be able to run the demo as seen in class with the following:
```
cd ui
python manage.py runserver
```
Then opening a web browser to `127.0.0.1:8000` if the port was not already occupied should show the website. Additionally, each of the algorithms inside the algorithms folder may have command line functionality that were not ported into the UI.