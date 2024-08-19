# ihunt

Information gathering tool that collects information using OSINT and AI, while remaining undetected by the target.

## Installation

### Option 1. Using Pip

The most easiest way is to install the Python package with `pip`.

```sh
pip install ihunt
ihunt --help
```

### Option 2. Using Rye

If you want to use the latest features (but unstable), clone the repository and run the following command.  
Assuming that you've already installed the [Rye](https://github.com/astral-sh/rye) project manager.

```sh
git clone https://github.com/hideckies/ihunt.git
cd ihunt
rye sync
rye run ihunt --help
```

<br />

## Usage

It's easy to use. Simply run one of the following commands:

```sh
# Research domain
ihunt example.com

# Research email address
ihunt user@example.com

# Research file (under development & not yet available)
ihunt ./example.exe

# Research hash (under development & not yet available)
ihunt ed076287532e86365e841e92bfc50d8c

# Research IP address
ihunt 8.8.8.8

# Research organization
ihunt Google

# Research person
ihunt "Elon Musk"

# Research URL
ihunt https://example.com
```

### Using API Keys

Some API need api keys, so if you want to collect information more, I recommend to set the api keys.  
To set them, copy the [.config.template](/.config.template) and set each api key, then execute with the `-c/--config` option:

```sh
ihunt -c .config example.com
```

Alternatively, we can directly set api keys to environment variables via command-line:

```sh
export IHUNT_APIKEY_ABUSEIPDB=xxxxxxxxxxxxxxx...
ihunt 8.8.8.8
```

### Output Format

Using `-o/--output` option, the result will be saved to a specified file. The ihunt detects the output format from the extension of the file path as below:

```sh
# JSON
ihunt -o output.json example.com

# YAML
ihunt -o output.yaml example.com

# Others (pretty print)
ihunt -o output.txt example.com
```