# Ghidra HTTP Analysis Server

## Starting the Server

```bash
# Install Flask if not already installed
pip install flask

# Set environment variables
export GHIDRA_INSTALL_DIR=c:\dev\projects\reveng-main\external\ghidra

# Start the server
python ghidra_http_server.py
```

The server will start on http://localhost:1337

## Testing

```bash
curl http://localhost:1337/health
```
