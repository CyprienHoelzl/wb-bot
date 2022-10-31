# The wb bot

This repo contains a script to automatically enroll to Working Bicycle campaigns

## Features

- Enroll to available campaign, if all conditions satisfied.
- Enroll to emailing list for campaign which is already full but still open.
- Save your credentials locally and reuse them on the next run.

## Run

### Prerequisites

You need to install the following:

- [Python 3](https://www.python.org/downloads/)

### First time

```bash
cd src
python3 -m pip install venv
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 wb_bot.py -h
```

### After the first time

```bash
cd src
source .venv/bin/activate
python3 wb_bot.py -h
```

### Examples

Enroll and save credentials (locally in `.wb-bot.json`)

```bash
python3 wb_bot.py --email "flbuetle" --save-credentials 
```

Enroll and use saved credentials

```bash
python3 wb_bot.py 
```

## Development

### Script

TODO: if the box is not installed on the bicycle, the script may work erratically. This functionality is not implemented

### Mock

```bash
cd mock
docker-compose up --build
```
