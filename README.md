This module is a simple wrapper for the Log4j Detect project found here:

https://github.com/whitesource/log4j-detect-distribution

The Log4j Detect project is a native Go binary which will scan any folder of jars for vulnerable files.  This module will download the latest binary for your OS and run it.
## Installation

Install the module like so:

```bash
install commandbox-log4j-detect
```

On first run, the module will download the latest version of the 3rd party library.  It will not check or download again on subsequent runs.  You can use the `--forceBinaryDownload` flag when scanning to force it to re-download the latest 3rd party library if you wish.


```bash
CommandBox> log4j-detect C:/websites/ --forceBinaryDownload
```


# Usage

Scan the current directory by running the command:


```bash
CommandBox> log4j-detect
```

Scan another directory by specying it as a parameter


```bash
CommandBox> log4j-detect C:/ColdFusion2021
CommandBox> log4j-detect /path/to/folder
```


Scan a list of directories for vulnerable Log4j jars

```bash
CommandBox> log4j-detect C:/foo,C:/bar,D:/baz
```

Scan a all drives on your machine.  This can take a very long time.

```bash
CommandBox> log4j-detect --scanAllDrives
```
