"""
Output module for IP WHOIS lookup tool.

This module provides functions for outputting WHOIS lookup results
in various formats.
"""

import os
import json
import logging
import csv
from typing import List, Dict, Any, Optional

import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from .util import WhoisResult

# Get logger
logger = logging.getLogger('whois_tool.output')

# Initialize console for rich output
console = Console()


def render_console(results: List[WhoisResult], verbose: bool = False) -> None:
    """
    Render WHOIS lookup results to the console.
    
    Args:
        results: List of WHOIS lookup results
        verbose: Whether to show verbose output
    """
    if not results:
        console.print("[yellow]No results to display[/]")
        return
    
    # Create table
    table = Table(title="IP WHOIS Lookup Results")
    
    # Add columns
    table.add_column("IP Address", style="cyan")
    table.add_column("Organization", style="green")
    table.add_column("Location", style="yellow")
    table.add_column("ASN", style="magenta")
    
    if verbose:
        table.add_column("Network", style="blue")
        table.add_column("Registration Date", style="bright_black")
        table.add_column("Source", style="bright_black")
    
    # Add rows
    for result in results:
        # Skip if no IP
        if not result.get('ip'):
            continue
        
        # Prepare location string
        location_parts = []
        if result.get('city'):
            location_parts.append(result['city'])
        if result.get('country'):
            location_parts.append(result['country'])
        location = ", ".join(location_parts) if location_parts else "Unknown"
        
        # Add row
        if verbose:
            table.add_row(
                result.get('ip', 'Unknown'),
                result.get('organization', 'Unknown'),
                location,
                result.get('asn', 'Unknown'),
                result.get('network', 'Unknown'),
                result.get('registered', 'Unknown'),
                result.get('source', 'Unknown')
            )
        else:
            table.add_row(
                result.get('ip', 'Unknown'),
                result.get('organization', 'Unknown'),
                location,
                result.get('asn', 'Unknown')
            )
    
    # Print table
    console.print(table)


def write_csv(results: List[WhoisResult], output_file: str) -> bool:
    """
    Write WHOIS lookup results to a CSV file.
    
    Args:
        results: List of WHOIS lookup results
        output_file: Path to output file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.debug(f"Writing {len(results)} results to CSV file: {output_file}")
        
        # Convert results to DataFrame
        df = pd.DataFrame(results)
        
        # Ensure minimal columns
        for col in ['ip', 'organization', 'country', 'city', 'asn', 'network', 'registered', 'source']:
            if col not in df.columns:
                df[col] = None
        
        # Write to CSV
        df.to_csv(output_file, index=False)
        
        logger.debug(f"Successfully wrote CSV file: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error writing CSV file: {e}")
        return False


def write_json(results: List[WhoisResult], output_file: str, include_raw: bool = False) -> bool:
    """
    Write WHOIS lookup results to a JSON file.
    
    Args:
        results: List of WHOIS lookup results
        output_file: Path to output file
        include_raw: Whether to include raw data in output
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.debug(f"Writing {len(results)} results to JSON file: {output_file}")
        
        # Copy results to avoid modifying original
        output_results = []
        
        for result in results:
            # Copy result
            output_result = result.copy()
            
            # Remove raw data if not requested
            if not include_raw and 'raw' in output_result:
                del output_result['raw']
            
            output_results.append(output_result)
        
        # Write to JSON
        with open(output_file, 'w') as f:
            json.dump(output_results, f, indent=2)
            
        logger.debug(f"Successfully wrote JSON file: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error writing JSON file: {e}")
        return False


def write_text(results: List[WhoisResult], output_file: str) -> bool:
    """
    Write WHOIS lookup results to a plain text file.
    
    Args:
        results: List of WHOIS lookup results
        output_file: Path to output file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.debug(f"Writing {len(results)} results to text file: {output_file}")
        
        with open(output_file, 'w') as f:
            f.write("IP WHOIS Lookup Results\n")
            f.write("======================\n\n")
            
            for i, result in enumerate(results, 1):
                f.write(f"Result {i}:\n")
                f.write(f"  IP Address:       {result.get('ip', 'Unknown')}\n")
                f.write(f"  Organization:     {result.get('organization', 'Unknown')}\n")
                f.write(f"  Country:          {result.get('country', 'Unknown')}\n")
                
                if result.get('city'):
                    f.write(f"  City:             {result['city']}\n")
                
                f.write(f"  ASN:              {result.get('asn', 'Unknown')}\n")
                f.write(f"  Network:          {result.get('network', 'Unknown')}\n")
                
                if result.get('registered'):
                    f.write(f"  Registration Date: {result['registered']}\n")
                
                f.write(f"  Source:           {result.get('source', 'Unknown')}\n")
                f.write("\n")
        
        logger.debug(f"Successfully wrote text file: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error writing text file: {e}")
        return False


def write_output(results: List[WhoisResult], output_file: str, format_type: str = 'csv') -> bool:
    """
    Write WHOIS lookup results to a file in the specified format.
    
    Args:
        results: List of WHOIS lookup results
        output_file: Path to output file
        format_type: Output format (csv, json, text)
        
    Returns:
        True if successful, False otherwise
    """
    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Write output based on format
    format_type = format_type.lower()
    
    if format_type == 'csv':
        return write_csv(results, output_file)
    elif format_type == 'json':
        return write_json(results, output_file)
    elif format_type == 'text':
        return write_text(results, output_file)
    else:
        logger.error(f"Unsupported output format: {format_type}")
        return False


def create_progress_bar() -> Progress:
    """
    Create a progress bar for bulk operations.
    
    Returns:
        Progress bar object
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[bold]{task.completed}/{task.total}"),
        TimeElapsedColumn()
    )


def process_with_progress(func, items, description="Processing"):
    """
    Process items with a progress bar.
    
    Args:
        func: Function to apply to each item
        items: List of items to process
        description: Progress bar description
        
    Returns:
        List of results
    """
    results = []
    
    with create_progress_bar() as progress:
        task = progress.add_task(description, total=len(items))
        
        for item in items:
            result = func(item)
            results.append(result)
            progress.update(task, advance=1)
    
    return results
