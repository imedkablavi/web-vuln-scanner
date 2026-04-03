import argparse
import yaml
import sys
from core.utils import setup_logger, logger
from core.request_manager import RequestManager
from core.crawler import Crawler
from core.scanner import ScannerEngine

def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner (Alpha)")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--config", default="config/default_config.yaml", help="Path to config file")
    parser.add_argument("--threads", type=int, help="Override thread count")
    args = parser.parse_args()

    # Load Config
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print("Config file not found. Using defaults.")
        # Fallback default config logic here...
        sys.exit(1)

    # Override Config with CLI args
    config["scanner"]["target"] = args.target
    if args.threads:
        config["concurrency"]["threads"] = args.threads
    
    # Add target domain to allowlist automatically
    from urllib.parse import urlparse
    domain = urlparse(args.target).netloc
    config["scanner"]["scope"]["allowlist"].append(domain)

    setup_logger(level=config["logging"]["level"], log_file=config["logging"]["file"])
    logger.info("Scanner initialized.")

    # Initialize Components
    req_manager = RequestManager(config["scanner"])
    crawler = Crawler(req_manager, config["scanner"])
    scanner = ScannerEngine(req_manager, config["scanner"])

    # 1. Crawl
    logger.info("Starting Crawler...")
    crawler.crawl(args.target)
    surfaces = crawler.get_surfaces()
    logger.info(f"Crawler finished. Found {len(surfaces)} attack surfaces.")

    # 2. Scan
    logger.info("Starting Scanner...")
    findings = scanner.scan(surfaces)

    # 3. Report
    print("\n=== Scan Report ===")
    if not findings:
        print("No vulnerabilities found.")
    else:
        for f in findings:
            print(f"[{f.severity}] {f.type}: {f.url} (Param: {f.parameter})")

if __name__ == "__main__":
    main()
