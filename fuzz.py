import argparse
import requests
import time
import concurrent.futures
from bs4 import BeautifulSoup
from colorama import Fore, Style
from threading import BoundedSemaphore

def print_help():
    """Print usage instructions and available options."""
    help_text = f"""
{Fore.CYAN}Usage:{Style.RESET_ALL}
    python tool.py -u <url> -w <wordlist> [options]

{Fore.CYAN}Options:{Style.RESET_ALL}
    -u, --url       Target URL with FUZZ as the placeholder for brute-forcing (required)
    -w, --wordlist  Path to the wordlist file (required)
    -t, --time      Time to wait (in seconds) after detecting WAF (default: 320)
    -s, --silent    Suppress output for specified response codes (comma-separated)
    -th, --threads  Number of requests to send per second (default: 50)
    -H, --header    Custom headers in the format 'Key:Value' (can be used multiple times)
    -h, --help      Show this help message and exit

{Fore.CYAN}Example:{Style.RESET_ALL}
    python tool.py -u https://example.com/FUZZ -w ./wordlist.txt -t 120 -s 403,503,421 -th 20 -H "Authorization: Bearer TOKEN" -H "Custom-Header: Value"
"""
    print(help_text)

def load_wordlist(wordlist_file):
    """Load directory and file names from the wordlist."""
    try:
        with open(wordlist_file, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"Wordlist file '{wordlist_file}' not found.")
        return []

def detect_waf(response, sequential_403_counter):
    """Refined WAF detection based on response patterns and headers."""
    if response.status_code == 403:
        sequential_403_counter[0] += 1
        if sequential_403_counter[0] >= 50:  # Trigger only after consecutive 403 responses
            print("Potential WAF or blocking detected after 50 consecutive 403 responses.")
            return True
    else:
        sequential_403_counter[0] = 0  # Reset the counter if a non-403 response is received

    if response.status_code == 429:
        print("Rate limiting detected (429 Too Many Requests).")
        return True

    if "captcha" in response.text.lower() or "access denied" in response.text.lower():
        print("WAF response detected in body text.")
        return True

    return False

def get_page_title(response):
    """Extract the page title from the HTML response."""
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title"
        return title.strip()
    except Exception as e:
        return f"Error extracting title: {e}"

def make_request(base_url, word, headers, wait_time, sequential_403_counter, silent_codes, total_words, progress_counter, semaphore):
    """Make a single HTTP request and handle the response."""
    with semaphore:
        url = base_url.replace("FUZZ", word)
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if detect_waf(response, sequential_403_counter):
                print(f"WAF or blocking detected. Waiting for reset period of {wait_time} seconds...")
                time.sleep(wait_time)
                return

            if response.status_code in silent_codes:
                return

            title = get_page_title(response)
            content_length = len(response.content)
            color = (
                Fore.BLUE if response.status_code == 200 else 
                Fore.GREEN if response.status_code in [301, 302, 401, 400] else 
                Fore.RED
            )
            title_color = Fore.YELLOW
            content_length_color = Fore.LIGHTGREEN_EX
            print(f"{color}[{response.status_code}] {url} - {title_color}[{title}]{Style.RESET_ALL} - {content_length_color}[{content_length}]{Style.RESET_ALL}")
        except requests.exceptions.SSLError:
            pass  # Suppress SSL Error output
        except requests.exceptions.InvalidURL:
            pass  # Suppress invalid URL errors
        except requests.exceptions.ConnectionError:
            pass  # Suppress connection errors
        except requests.RequestException:
            pass  # Suppress general request exceptions
        finally:
            # Update progress
            progress_counter[0] += 1
            percent_done = (progress_counter[0] / total_words) * 100
            print(f"{Fore.CYAN}Progress: {percent_done:.2f}% completed.{Style.RESET_ALL}", end="\r")

def brute_force(base_url, wordlist, wait_time=320, silent_codes=None, threads=50, headers=None):
    """Perform brute-forcing with WAF handling using multithreading."""
    sequential_403_counter = [0]  # Using a list to allow modification inside threads
    total_words = len(wordlist)
    progress_counter = [0]  # Shared counter for progress tracking

    semaphore = BoundedSemaphore(threads)  # Control the number of threads per second

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(make_request, base_url, word, headers, wait_time, sequential_403_counter, silent_codes, total_words, progress_counter, semaphore) 
            for word in wordlist
        ]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Directory and File Brute-Forcing Tool",
        add_help=False  # Disable the default help to avoid conflicts
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ as the placeholder for brute-forcing")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-t", "--time", type=int, default=320, help="Time to wait (in seconds) after WAF detection")
    parser.add_argument("-s", "--silent", help="Comma-separated response codes to suppress output (e.g., 403,503,421)")
    parser.add_argument("-th", "--threads", type=int, default=50, help="Number of requests to send per second")
    parser.add_argument("-H", "--header", action="append", help="Custom headers in the format 'Key:Value' (can be used multiple times)")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message and exit")

    args = parser.parse_args()

    # Show help if -h is provided
    if args.help:
        print_help()
    else:
        # Parse silent codes
        silent_codes = [int(code.strip()) for code in args.silent.split(',')] if args.silent else []

        # Parse and incorporate custom headers
        custom_headers = {}
        if args.header:
            for header in args.header:
                try:
                    key, value = header.split(":", 1)
                    custom_headers[key.strip()] = value.strip()
                except ValueError:
                    print(f"Invalid header format: {header}. Headers should be in the format 'Key:Value'. Exiting.")
                    exit(1)

        # Combine default and custom headers
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; BruteForcer/1.0)"
        }
        headers.update(custom_headers)

        # Load the wordlist
        wordlist = load_wordlist(args.wordlist)

        # Validate inputs
        if not wordlist:
            print("No valid entries found in the wordlist. Exiting.")
        elif "FUZZ" not in args.url:
            print("Error: The URL must contain the placeholder 'FUZZ'. Exiting.")
        else:
            # Start brute-forcing
            brute_force(args.url, wordlist, args.time, silent_codes, args.threads, headers)
