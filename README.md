# unegg

Extract files from egg files.

## Installation

```
brew install blurfx/tap/unegg
```

## Usage

```
Usage: unegg [options] <archive.egg>
  -C string
        destination directory (default: archive base name)
  -j int
        number of parallel workers (default 14)
  -l    list archive contents
  -p string
        password for encrypted archives
  -q    quiet mode (no progress output)
```

Example usage

```
unegg photos.egg
```
