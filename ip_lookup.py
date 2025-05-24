#!/usr/bin/env python3
"""
IP WHOIS Lookup Tool - Command-line tool for IP WHOIS lookups.

This script provides a command-line interface for looking up WHOIS information
for IP addresses using multiple sources and methods.
"""

import sys
import os
import argparse
import logging
from typing import List, Optional, Dict, Any, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rprint

from whois_tool import __version__
from whois_tool.engine import WhoisEngine
from whois_tool.util import WhoisResult
from whois_tool.output import render_console, write_output
from whois_tool.resolvers import get_available_resolvers

# Initialize console for rich output
console = Console()

# Configure logging
def setup_logging(verbose: bool = False):
    """
    Set up logging configuration.
    
    Args:
        verbose: Whether to enable verbose logging
    """
    log_dir = os.path.join(os.path.dirname(__file__), 'data', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'ip_lookup.log')
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # Create console handler if verbose
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(
            '%(levelname)s: %(message)s'
        ))
        root_logger.addHandler(console_handler)
    
    # Add handlers
    root_logger.addHandler(file_handler)


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Args:
        args: Command-line arguments (None for sys.argv)
        
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="IP WHOIS Lookup Tool - Look up WHOIS information for IP addresses",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '-i', '--ip',
        action='append',
        help='IP address to look up (can be specified multiple times)'
    )
    input_group.add_argument(
        '-f', '--file',
        help='File containing IP addresses (one per line)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output file path'
    )
    output_group.add_argument(
        '--format',
        choices=['csv', 'json', 'text'],
        default='csv',
        help='Output format'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output'
    )
    
    # Lookup options
    lookup_group = parser.add_argument_group('Lookup Options')
    lookup_group.add_argument(
        '--lookup-method',
        choices=['auto', 'ipwhois', 'pythonwhois', 'system'],
        default='auto',
        help='WHOIS lookup method'
    )
    lookup_group.add_argument(
        '--force-system-whois',
        action='store_true',
        help='Force use of system whois command'
    )
    lookup_group.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable caching of results'
    )
    lookup_group.add_argument(
        '--timeout',
        type=float,
        default=30.0,
        help='Timeout for WHOIS lookups in seconds'
    )
    lookup_group.add_argument(
        '--rate-limit',
        type=float,
        default=1.0,
        help='Minimum time between requests in seconds'
    )
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument(
        '--no-parallel',
        action='store_true',
        help='Disable parallel processing'
    )
    perf_group.add_argument(
        '--max-workers',
        type=int,
        default=8,
        help='Maximum number of worker threads for parallel processing'
    )
    
    # Other options
    other_group = parser.add_argument_group('Other Options')
    other_group.add_argument(
        '--clean-cache',
        action='store_true',
        help='Clean expired cache entries before running'
    )
    other_group.add_argument(
        '--version',
        action='version',
        version=f'IP WHOIS Lookup Tool v{__version__}',
        help='Show version information and exit'
    )
    
    # Parse arguments
    parsed_args = parser.parse_args(args)
    
    # Handle force-system-whois
    if parsed_args.force_system_whois:
        parsed_args.lookup_method = 'system'
    
    # Validate arguments
    if not parsed_args.ip and not parsed_args.file:
        parser.error("At least one IP address or a file must be specified")
    
    return parsed_args


def get_ip_addresses(args: argparse.Namespace) -> List[str]:
    """
    Get IP addresses from command-line arguments or file.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        List of IP addresses
    """
    ips = []
    
    # Get IPs from command-line
    if args.ip:
        ips.extend(args.ip)
    
    # Get IPs from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_ips = [line.strip() for line in f if line.strip()]
                ips.extend(file_ips)
        except Exception as e:
            console.print(f"[bold red]Error reading IP file:[/] {e}")
            sys.exit(1)
    
    return ips


def main():
    """
    Main entry point for the application.
    """
    try:
        # Parse command-line arguments
        args = parse_args()
        
        # Set up logging
        setup_logging(args.verbose)
        
        # Print banner
        console.print("[bold cyan]IP WHOIS Lookup Tool[/]", highlight=False)
        console.print(f"Version: {__version__}", highlight=False)
        console.print(f"Available resolvers: {', '.join(get_available_resolvers())}", highlight=False)
        console.print()
        
        # Initialize engine
        engine = WhoisEngine(
            lookup_method=args.lookup_method,
            use_cache=not args.no_cache,
            timeout=args.timeout,
            rate_limit=args.rate_limit
        )
        
        # Clean cache if requested
        if args.clean_cache:
            with console.status("[bold blue]Cleaning cache...[/]", spinner="dots"):
                cleaned = engine.clean_cache()
            console.print(f"Cleaned {cleaned} expired cache entries")
        
        # Get IP addresses
        ips = get_ip_addresses(args)
        
        if not ips:
            console.print("[bold red]Error:[/] No IP addresses provided")
            return 1
        
        console.print(f"Processing {len(ips)} IP addresses...")
        
        # Process IP addresses
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold]{task.completed}/{task.total}"),
            TimeRemainingColumn()
        ) as progress:
            task_id = progress.add_task("Looking up IP addresses...", total=len(ips))
            
            # Monkey patch the progress reporting into the engine
            original_lookup = engine.lookup_ip
            
            def lookup_with_progress(ip):
                result = original_lookup(ip)
                progress.update(task_id, advance=1)
                return result
            
            engine.lookup_ip = lookup_with_progress
            
            # Process IPs
            results = engine.process_ips(
                ips,
                parallel=not args.no_parallel,
                max_workers=args.max_workers
            )
        
        # Output results
        if not results:
            console.print("[bold yellow]Warning:[/] No results found")
            return 0
        
        console.print(f"[bold green]Found {len(results)} results[/]")
        
        # Write output to file if requested
        if args.output:
            console.print(f"Writing results to {args.output}...")
            success = write_output(results, args.output, args.format)
            if success:
                console.print(f"[bold green]Results written to {args.output}[/]")
            else:
                console.print(f"[bold red]Error writing to {args.output}[/]")
                return 1
        else:
            # Display results in console
            render_console(results, args.verbose)
        
        return 0
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation canceled by user[/]")
        return 130
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        if args.verbose:
            import traceback
            console.print_exception()
        return 1


if __name__ == "__main__":
    sys.exit(main())
