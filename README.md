# Python Port Scanner

A simple yet efficient Python-based port scanner that utilizes different methods to scan ports. Each folder has its own way of building the scanner.
1. `simple` just iterates over a for loop, sends request one at a time
2. `concurrent` utilizes ThreadPoolExecutor to manage concurrent executions
3. `async` uses coroutines with an event loop for async tasks

## Features

- Scans multiple ports concurrently using `ThreadPoolExecutor` from the `concurrent.futures` module.
- Supports both single-port and port range scanning.
- Provides fast scanning performance by leveraging multi-threading.
- Handles network timeouts and errors gracefully.

## Requirements

- Python 3.6 or higher

## Installation

1.**Clone the Repository:**

   ```bash
   git clone https://github.com/MuratZamir/PyScanner.git
   cd PyScanner
   python3 main.py <ip> <range>
```

## Example Output

```bash
PORT    STATE  SERVICE
21/tcp  open   ftp
22/tcp  open   ssh
80/tcp  open   http
443/tcp open   https
```

## Limitations

- The script relies on Python's threading model, which is not suitable for CPU-bound tasks due to the Global Interpreter Lock (GIL).
- Performance may vary depending on network conditions and the target server's response.

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue if you find a bug or have a feature request.


