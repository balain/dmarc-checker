# DMARC Report Analyzer

A Python script that analyzes DMARC (Domain-based Message Authentication, Reporting & Conformance) reports using a local Ollama LLM to identify security concerns, authentication failures, and suspicious patterns.

## Features

- **Multiple Input Formats**: Supports both XML and gzip-compressed (.gz) DMARC reports
- **Ollama Integration**: Uses local Ollama LLM for intelligent analysis
- **Model Management**: Automatically detects available models and allows setting a default
- **Monitoring Mode**: Watches a directory for new reports when run without arguments
- **Simple Output**: Prints "ok" if no concerns, or lists issues if found

## Requirements

- Python 3.8+
- Ollama installed and running locally
- At least one Ollama model installed

## Installation

1. Install dependencies using `uv`:

```bash
uv pip install -r requirements.txt
```

2. Ensure Ollama is running:

```bash
ollama serve
```

3. Install at least one Ollama model (e.g., llama3):

```bash
ollama pull llama3
```

## Usage

### Analyze Specific Files

```bash
python dmarc_analyzer.py report.xml
python dmarc_analyzer.py report.xml.gz
python dmarc_analyzer.py report1.xml report2.xml.gz
```

### Monitor Directory

When run without arguments, the script monitors `~/Downloads/dmarc-report-inbox` for new files:

```bash
python dmarc_analyzer.py
```

The script will:
- Process any existing files in the directory on startup
- Watch for new files and process them automatically
- Continue running until interrupted (Ctrl+C)

### Custom Ollama URL

If Ollama is running on a different host/port:

```bash
python dmarc_analyzer.py --ollama-url http://localhost:11434 report.xml
```

## Model Selection

On first run (or if the default model is unavailable), you'll be prompted to select a model:

```
Available Ollama models:
  1. llama3
  2. llama3.1
  3. mistral

Select a model (1-3) or 'q' to quit: 1
Set 'llama3' as default for future runs? (y/n): y
```

Your selection is saved to `~/.dmarc_analyzer_config.json` for future runs.

## Output

- **No concerns**: Prints `ok` to STDOUT
- **Issues found**: Prints a list of concerns/issues, one per line

## Configuration

The default model preference is stored in `~/.dmarc_analyzer_config.json`. You can edit this file directly or let the script update it when selecting a model.

## Error Handling

The script handles:
- Missing or corrupted files
- Invalid XML structure
- Ollama service unavailability
- Network timeouts
- File permission errors

Errors are printed to STDERR, while analysis results go to STDOUT.

