"""
CLI for IP WHOIS lookups.

Handles command-line arguments, sets up logging, and runs the lookup process.
"""

import sys
import os
import argparse
import logging
from typing import List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from whois_tool import __version__
from whois_tool.engine import WhoisEngine
from whois_tool.output import render_console, write_output
from whois_tool.resolvers import get_available_resolvers

console = Console()

def setup_logging(verbose=False):
    """Sets up logging - file always, console only in verbose mode"""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Probably should make this configurable at some point
    log_file = os.path.join(log_dir, 'ip_lookup.log')
    
    root_logger = logging.getLogger()
    if verbose:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)
    
    # Always log to file
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)  # Debug to file regardless of console level
    fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    root_logger.addHandler(fh)
    
    # Maybe log to console too
    if verbose:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        root_logger.addHandler(ch)
        
        # Log a test message - useful for debugging logging itself
        logging.debug("Verbose logging enabled")


def parse_args(args=None):
    """Parses command line args and returns the parsed namespace"""
    parser = argparse.ArgumentParser(
        description="IP WHOIS Lookup Tool - Look up WHOIS information for IP addresses",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Where to get the IPs from
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        '-i', '--ip',
        action='append',
        help='IP address to look up (use multiple times for multiple IPs)'
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
                file_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                ips.extend(file_ips)
        except Exception as e:
            console.print(f"[bold red]Error reading IP file:[/] {e}")
            sys.exit(1)
    
    return ips


def main(argv=None):
    """Where the magic happens"""
    try:
        # Parse args and set up environment
        args = parse_args(argv)
        setup_logging(args.verbose)
        
        # Say hello!
        console.print("[bold cyan]IP WHOIS Lookup Tool[/]", highlight=False)
        console.print(f"Version: {__version__}", highlight=False)
        
        # Show available resolvers - useful for debugging
        resolvers = get_available_resolvers()
        if resolvers:
            console.print(f"Available resolvers: {', '.join(resolvers)}", highlight=False)
        else:
            console.print("[yellow]Warning: No resolvers available![/]")
            return 1
        console.print()
        
        # Fire up the engine
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
        
        # Show what we found (or didn't)
        if not results:
            console.print("🤷 [bold yellow]No results found - maybe try a different lookup method?[/]")
            return 0
        
        num_results = len(results)
        if num_results == 1:
            console.print("🎯 [bold green]Found 1 result[/]")
        else:
            console.print(f"🎯 [bold green]Found {num_results} results[/]")
        
        # Output to file or screen
        if args.output:
            console.print(f"📝 Writing to {args.output}...")
            if write_output(results, args.output, args.format):
                console.print(f"✅ [bold green]Results saved to {args.output}[/]")
            else:
                console.print(f"❌ [bold red]Couldn't write to {args.output}![/]")
                logging.error(f"Failed to write output to {args.output}")
                return 1
        else:
            render_console(results, args.verbose)
        
        return 0
        
    except KeyboardInterrupt:
        console.print("\n👋 [bold yellow]Stopped by user[/]")
        return 130
    except Exception as e:
        # Something went wrong
        console.print(f"💥 [bold red]Oops![/] {e}")
        logging.error(f"Unhandled exception: {e}")
        
        # Show traceback in verbose mode
        if getattr(args, 'verbose', False):
            import traceback
            console.print_exception()
        
        # Tell user what to do next
        console.print("\nTry with --verbose for more details, or check the logs.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
