#!/usr/bin/env python3
"""
DMARC Report Analyzer with Ollama Integration

Analyzes DMARC reports (XML or gzip-compressed) using a local Ollama LLM
to identify security concerns and authentication issues.
"""

import argparse
import gzip
import json
import select
import shutil
import sys
import time
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class ConfigManager:
    """Manages configuration file for default Ollama model."""
    
    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path.home() / ".dmarc_analyzer_config.json"
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def save_config(self, config: dict) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save config: {e}", file=sys.stderr)
    
    def get_default_model(self) -> Optional[str]:
        """Get the default model from config."""
        return self.config.get("default_model")
    
    def set_default_model(self, model: str) -> None:
        """Set the default model in config."""
        self.config["default_model"] = model
        self.save_config(self.config)


class OllamaClient:
    """Client for interacting with Ollama API."""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url.rstrip("/")
    
    def check_connection(self) -> bool:
        """Check if Ollama service is available."""
        try:
            print("Connecting to Ollama service...", file=sys.stderr)
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                print("Connected to Ollama service", file=sys.stderr)
                return True
            return False
        except requests.RequestException:
            return False
    
    def get_available_models(self) -> list[str]:
        """Get list of available Ollama models."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            response.raise_for_status()
            data = response.json()
            models = [model["name"] for model in data.get("models", [])]
            return sorted(models)
        except requests.RequestException as e:
            print(f"Error fetching models: {e}", file=sys.stderr)
            return []
    
    def select_model(self, config_manager: ConfigManager) -> Optional[str]:
        """Select model, using default if available, otherwise prompting user."""
        default_model = config_manager.get_default_model()
        available_models = self.get_available_models()
        
        if not available_models:
            print("Error: No Ollama models found. Please install at least one model.", file=sys.stderr)
            return None
        
        # Check if default model is still available
        if default_model and default_model in available_models:
            print(f"Using default model: {default_model}", file=sys.stderr)
            return default_model
        
        # Prompt user to select a model
        print("Available Ollama models:", file=sys.stderr)
        for i, model in enumerate(available_models, 1):
            print(f"  {i}. {model}", file=sys.stderr)
        
        while True:
            try:
                choice = input(f"\nSelect a model (1-{len(available_models)}) or 'q' to quit: ").strip()
                if choice.lower() == 'q':
                    return None
                
                idx = int(choice) - 1
                if 0 <= idx < len(available_models):
                    selected_model = available_models[idx]
                    save_default = input(f"Set '{selected_model}' as default for future runs? (y/n): ").strip().lower()
                    if save_default == 'y':
                        config_manager.set_default_model(selected_model)
                    return selected_model
                else:
                    print(f"Please enter a number between 1 and {len(available_models)}", file=sys.stderr)
            except ValueError:
                print("Please enter a valid number", file=sys.stderr)
            except (EOFError, KeyboardInterrupt):
                return None
    
    def analyze_dmarc_report(self, model: str, xml_content: str) -> str:
        """Send DMARC report to Ollama for analysis."""
        print(f"Analyzing report with {model}...", file=sys.stderr)
        prompt = """You are a cybersecurity analyst reviewing a DMARC (Domain-based Message Authentication, Reporting & Conformance) report.

Analyze the following DMARC report XML and identify any security concerns, authentication failures, suspicious patterns, or issues that require attention.

Focus on:
- SPF (Sender Policy Framework) authentication failures
- DKIM (DomainKeys Identified Mail) authentication failures
- Unusual sending patterns or sources
- Potential email spoofing attempts
- High failure rates
- Suspicious IP addresses or domains
- Any anomalies in the report data

If everything looks normal and there are no concerns, respond with only the word "ok" (lowercase).

If there are concerns, list them clearly and concisely, one per line.

DMARC Report XML:
"""
        prompt += xml_content
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=300,  # 5 minute timeout for LLM processing
            )
            response.raise_for_status()
            result = response.json()
            analysis = result.get("response", "").strip()
            print("Analysis complete", file=sys.stderr)
            return analysis
        except requests.RequestException as e:
            print(f"Error communicating with Ollama: {e}", file=sys.stderr)
            return ""


class FileProcessor:
    """Handles file processing: decompression and XML extraction."""
    
    @staticmethod
    def read_file(file_path: Path) -> Optional[str]:
        """Read file content, handling gzip compression."""
        try:
            print(f"Reading file: {file_path.name}", file=sys.stderr)
            if file_path.suffix == ".gz":
                with gzip.open(file_path, "rt", encoding="utf-8") as f:
                    content = f.read()
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            
            # Validate XML structure
            try:
                ElementTree.fromstring(content)
            except ElementTree.ParseError as e:
                print(f"Warning: Invalid XML in {file_path}: {e}", file=sys.stderr)
                return None
            
            return content
        except gzip.BadGzipFile:
            print(f"Error: {file_path} is not a valid gzip file", file=sys.stderr)
            return None
        except IOError as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return None
        except UnicodeDecodeError as e:
            print(f"Error decoding {file_path}: {e}", file=sys.stderr)
            return None


class DMARCFileHandler(FileSystemEventHandler):
    """Handler for file system events in monitoring mode."""
    
    def __init__(self, ollama_client: OllamaClient, model: str, processed_files: set, processed_dir: Path):
        self.ollama_client = ollama_client
        self.model = model
        self.processed_files = processed_files
        self.processed_dir = processed_dir
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path.suffix in (".xml", ".gz"):
                self._process_file(file_path)
    
    def _process_file(self, file_path: Path):
        """Process a DMARC report file."""
        if file_path in self.processed_files:
            return
        
        self.processed_files.add(file_path)
        
        # Small delay to ensure file is fully written
        time.sleep(0.5)
        
        analyze_file(file_path, self.ollama_client, self.model, self.processed_dir)


def move_to_processed(file_path: Path, processed_dir: Path) -> bool:
    """Move file to processed directory."""
    try:
        processed_dir.mkdir(parents=True, exist_ok=True)
        destination = processed_dir / file_path.name
        # Handle name conflicts by appending a number
        counter = 1
        while destination.exists():
            stem = file_path.stem
            suffix = file_path.suffix
            destination = processed_dir / f"{stem}_{counter}{suffix}"
            counter += 1
        
        shutil.move(str(file_path), str(destination))
        print(f"Moved to: {destination}", file=sys.stderr)
        return True
    except (IOError, OSError) as e:
        print(f"Warning: Could not move file to processed directory: {e}", file=sys.stderr)
        return False


def analyze_file(file_path: Path, ollama_client: OllamaClient, model: str, processed_dir: Optional[Path] = None) -> bool:
    """Analyze a single DMARC report file."""
    print(f"Processing: {file_path}", file=sys.stderr)
    xml_content = FileProcessor.read_file(file_path)
    if xml_content is None:
        return False
    
    analysis = ollama_client.analyze_dmarc_report(model, xml_content)
    
    if not analysis:
        print(f"Error: Failed to analyze {file_path}", file=sys.stderr)
        return False
    
    # Output result to STDOUT
    if analysis.lower() == "ok":
        print("ok")
    else:
        print(analysis)
    
    # Move file to processed directory if specified
    if processed_dir is not None:
        move_to_processed(file_path, processed_dir)
    
    return True


def get_existing_reports(directory: Path) -> list[Path]:
    """Get list of existing report files in directory."""
    reports = []
    for file_path in directory.glob("*.xml"):
        if file_path.is_file() and file_path.parent == directory:
            reports.append(file_path)
    for file_path in directory.glob("*.gz"):
        if file_path.is_file() and file_path.parent == directory:
            reports.append(file_path)
    return reports


def process_existing_files(directory: Path, ollama_client: OllamaClient, model: str) -> set[Path]:
    """Process existing files in directory and return set of processed file paths."""
    processed_dir = directory / "processed"
    print(f"Processed files will be moved to: {processed_dir}", file=sys.stderr)
    
    processed_files = set()
    reports = get_existing_reports(directory)
    
    if reports:
        print(f"Found {len(reports)} report(s) to process...", file=sys.stderr)
        for file_path in reports:
            analyze_file(file_path, ollama_client, model, processed_dir)
            processed_files.add(file_path)
    else:
        print("No existing reports found in directory", file=sys.stderr)
    
    return processed_files


def prompt_monitor_mode(timeout: int = 30) -> bool:
    """Prompt user if they want to run in monitor mode with timeout. Returns True if yes, False otherwise."""
    print(f"\nStart monitoring for new reports? (y/n) [default: n, timeout: {timeout}s]: ", end="", file=sys.stderr)
    sys.stderr.flush()
    
    start_time = time.time()
    response = ""
    last_displayed_seconds = timeout
    
    while time.time() - start_time < timeout:
        elapsed = time.time() - start_time
        remaining_seconds = int(timeout - elapsed)
        
        # Update countdown display every second
        if remaining_seconds != last_displayed_seconds:
            last_displayed_seconds = remaining_seconds
            print(f"\rStart monitoring for new reports? (y/n) [default: n, timeout: {remaining_seconds}s]: ", end="", file=sys.stderr)
            sys.stderr.flush()
        
        if select.select([sys.stdin], [], [], 0.1)[0]:
            try:
                response = sys.stdin.readline().strip().lower()
                print("", file=sys.stderr)  # New line after response
                break
            except (EOFError, KeyboardInterrupt):
                print("", file=sys.stderr)  # New line after interrupt
                break
        time.sleep(0.1)
    
    if not response:
        print("n", file=sys.stderr)  # Echo default
        print("No response received, defaulting to 'no'", file=sys.stderr)
        return False
    
    return response == "y"


def start_monitoring(directory: Path, ollama_client: OllamaClient, model: str, processed_files: set[Path]):
    """Start monitoring directory for new DMARC report files."""
    processed_dir = directory / "processed"
    
    # Set up file system watcher
    event_handler = DMARCFileHandler(ollama_client, model, processed_files, processed_dir)
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=False)
    observer.start()
    
    try:
        print(f"Monitoring {directory} for new DMARC reports... (Press Ctrl+C to stop)", file=sys.stderr)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...", file=sys.stderr)
        observer.stop()
    observer.join()


def monitor_directory(directory: Path, ollama_client: OllamaClient, model: str):
    """Monitor directory for new DMARC report files."""
    if not directory.exists():
        print(f"Error: Directory {directory} does not exist", file=sys.stderr)
        sys.exit(1)
    
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory", file=sys.stderr)
        sys.exit(1)
    
    # Process existing files
    processed_files = process_existing_files(directory, ollama_client, model)
    
    # Check if there were existing files
    if processed_files:
        # Ask user if they want to monitor
        if prompt_monitor_mode():
            start_monitoring(directory, ollama_client, model, processed_files)
        else:
            print("Exiting", file=sys.stderr)
    else:
        # No existing files, start monitoring immediately
        start_monitoring(directory, ollama_client, model, processed_files)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze DMARC reports using Ollama LLM"
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="DMARC report files to analyze (XML or .gz). If not provided, monitors ~/Downloads/dmarc-report-inbox"
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="Ollama API base URL (default: http://localhost:11434)"
    )
    
    args = parser.parse_args()
    
    # Initialize components
    config_manager = ConfigManager()
    ollama_client = OllamaClient(args.ollama_url)
    
    # Check Ollama connection
    if not ollama_client.check_connection():
        print("Error: Cannot connect to Ollama service. Is it running?", file=sys.stderr)
        sys.exit(1)
    
    # Select model
    model = ollama_client.select_model(config_manager)
    if not model:
        print("Error: No model selected", file=sys.stderr)
        sys.exit(1)
    
    # Process files or monitor directory
    if args.files:
        # Process specified files
        # For direct file processing, move to processed subdirectory relative to each file's parent
        for file_arg in args.files:
            file_path = Path(file_arg).resolve()
            if not file_path.exists():
                print(f"Error: File not found: {file_path}", file=sys.stderr)
                continue
            processed_dir = file_path.parent / "processed"
            analyze_file(file_path, ollama_client, model, processed_dir)
    else:
        # Monitor directory
        monitor_dir = Path.home() / "Downloads" / "dmarc-report-inbox"
        monitor_directory(monitor_dir, ollama_client, model)


if __name__ == "__main__":
    main()

