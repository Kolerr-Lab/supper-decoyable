#!/usr/bin/env python3
"""
DECOYABLE Linux Kernel Python Stress Test

Extreme stress test that scans the entire Python subset of the Linux Kernel
to validate performance, stability, and enterprise-grade capabilities.

Requirements:
- Full scan: Traverse linux/ repo and scan all Python files (~315 expected)
- Concurrency: Split into 4-5 partitions and run scans concurrently (async-safe)
- Metrics: Log total files scanned, scan duration, memory usage, findings count
- Resilience: No crashes; handle errors gracefully
- Kafka Integration: Push findings to decoyable.attacks topic if enabled
- Fallback: Continue with in-memory cache if Kafka/Redis disabled
- Output: Comprehensive summary report

Goal: Prove DECOYABLE can scan Linux Kernel Python subset sub-minute with real findings.
"""

import asyncio
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import psutil
import json

from decoyable.core.config import Settings
from decoyable.core.logging import LoggingService, get_logger, setup_logging_service
from decoyable.core.registry import ServiceRegistry
from decoyable.scanners.service import ScannerService

# Optional Kafka import
try:
    from decoyable.streaming.kafka_producer import KafkaAttackProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KafkaAttackProducer = None
    KAFKA_AVAILABLE = False


class LinuxKernelStressTest:
    """Stress test for scanning Linux Kernel Python files."""

    def __init__(self, config: Settings, registry: ServiceRegistry, logging_service: LoggingService):
        self.config = config
        self.registry = registry
        self.logging_service = logging_service
        self.logger = get_logger("stress_test.kernel")

        # Get services from registry
        self.scanner_service = registry.get_by_name("scanner_service")
        self.kafka_producer = None

        # Metrics tracking
        self.start_time = time.time()
        self.memory_start = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.memory_peak = self.memory_start

        # Results
        self.files_scanned = 0
        self.secrets_found = 0
        self.sast_issues_found = 0
        self.deps_issues_found = 0
        self.errors = []

        # Partitions for concurrent scanning
        self.num_partitions = 5

    async def discover_python_files(self, base_path: Path) -> List[Path]:
        """Discover all Python files in the Linux kernel directory."""
        self.logger.info(f"Discovering Python files in {base_path}")
        python_files = []

        if not base_path.exists():
            raise FileNotFoundError(f"Linux kernel path does not exist: {base_path}")

        # Walk through directory and find .py files
        for root, dirs, files in os.walk(base_path):
            # Skip common exclude patterns
            dirs[:] = [d for d in dirs if not any(excl in d for excl in ['.git', '__pycache__', '.venv', 'venv'])]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)

        self.logger.info(f"Found {len(python_files)} Python files")
        return python_files

    def partition_files(self, files: List[Path]) -> List[List[Path]]:
        """Split files into partitions for concurrent scanning."""
        partitions = []
        partition_size = len(files) // self.num_partitions

        for i in range(self.num_partitions):
            start_idx = i * partition_size
            if i == self.num_partitions - 1:
                # Last partition gets remaining files
                end_idx = len(files)
            else:
                end_idx = (i + 1) * partition_size

            partitions.append(files[start_idx:end_idx])

        self.logger.info(f"Split {len(files)} files into {len(partitions)} partitions")
        for i, partition in enumerate(partitions):
            self.logger.debug(f"Partition {i}: {len(partition)} files")

        return partitions

    async def scan_partition(self, partition_id: int, files: List[Path]) -> Dict:
        """Scan a partition of files concurrently."""
        self.logger.info(f"Starting partition {partition_id} with {len(files)} files")

        partition_results = {
            "partition_id": partition_id,
            "files_scanned": 0,
            "secrets_found": 0,
            "sast_issues": 0,
            "deps_issues": 0,
            "findings": [],
            "errors": []
        }

        semaphore = asyncio.Semaphore(10)  # Limit concurrent file scans

        async def scan_single_file(file_path: Path):
            async with semaphore:
                try:
                    # Scan for secrets
                    secrets_report = await self.scanner_service.scan_secrets(str(file_path))
                    secrets_count = len(secrets_report.results)

                    # Scan for SAST issues
                    sast_report = await self.scanner_service.scan_sast(str(file_path))
                    sast_count = len(sast_report.results)

                    # Scan for dependencies
                    deps_report = await self.scanner_service.scan_dependencies(str(file_path))
                    deps_count = len(deps_report.results)

                    # Collect findings for Kafka
                    findings = []
                    if secrets_count > 0:
                        findings.extend([{
                            "type": "secret",
                            "file": str(file_path),
                            "findings": [f.__dict__ for f in secrets_report.results]
                        }])

                    if sast_count > 0:
                        findings.extend([{
                            "type": "sast",
                            "file": str(file_path),
                            "findings": [v.__dict__ for v in sast_report.results]
                        }])

                    if deps_count > 0:
                        findings.extend([{
                            "type": "dependency",
                            "file": str(file_path),
                            "findings": [d.__dict__ for d in deps_report.results]
                        }])

                    return {
                        "file": str(file_path),
                        "secrets": secrets_count,
                        "sast": sast_count,
                        "deps": deps_count,
                        "findings": findings
                    }

                except Exception as e:
                    self.logger.warning(f"Error scanning {file_path}: {e}")
                    return {
                        "file": str(file_path),
                        "error": str(e),
                        "secrets": 0,
                        "sast": 0,
                        "deps": 0,
                        "findings": []
                    }

        # Scan all files in this partition concurrently
        tasks = [scan_single_file(file_path) for file_path in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                partition_results["errors"].append(str(result))
                continue

            partition_results["files_scanned"] += 1
            partition_results["secrets_found"] += result["secrets"]
            partition_results["sast_issues"] += result["sast"]
            partition_results["deps_issues"] += result["deps"]
            partition_results["findings"].extend(result["findings"])

            # Send to Kafka if enabled
            if self.kafka_producer and result["findings"]:
                try:
                    for finding in result["findings"]:
                        await self.kafka_producer.publish_attack_event(finding)
                except Exception as e:
                    self.logger.warning(f"Failed to send to Kafka: {e}")

        self.logger.info(f"Partition {partition_id} completed: {partition_results['files_scanned']} files, "
                        f"{partition_results['secrets_found']} secrets, "
                        f"{partition_results['sast_issues']} SAST issues, "
                        f"{partition_results['deps_issues']} dep issues")

        return partition_results

    def update_memory_peak(self):
        """Update memory peak usage."""
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.memory_peak = max(self.memory_peak, current_memory)

    async def run_stress_test(self, linux_path: Path) -> Dict:
        """Run the complete stress test."""
        self.logger.info("🚀 Starting DECOYABLE Linux Kernel Python Stress Test")
        self.logger.info(f"Target: {linux_path}")
        self.logger.info(f"Partitions: {self.num_partitions}")

        # Initialize Kafka producer if available
        if KAFKA_AVAILABLE and self.config.kafka_enabled:
            try:
                self.kafka_producer = KafkaAttackProducer()
                await self.kafka_producer.start()
                self.logger.info("Kafka producer initialized and started")
            except Exception as e:
                self.logger.warning(f"Kafka producer initialization failed: {e}")
                self.kafka_producer = None

        kafka_enabled = self.kafka_producer is not None
        self.logger.info(f"Kafka enabled: {kafka_enabled}")

        try:
            # Discover Python files
            python_files = await self.discover_python_files(linux_path)
            if not python_files:
                raise ValueError("No Python files found in Linux kernel directory")

            # Partition files
            partitions = self.partition_files(python_files)

            # Run concurrent scans
            self.logger.info("🔄 Starting concurrent partition scans...")
            partition_tasks = [
                self.scan_partition(i, partition)
                for i, partition in enumerate(partitions)
            ]

            # Run all partitions concurrently
            partition_results = await asyncio.gather(*partition_tasks, return_exceptions=True)

            # Aggregate results
            for result in partition_results:
                if isinstance(result, Exception):
                    self.errors.append(str(result))
                    continue

                self.files_scanned += result["files_scanned"]
                self.secrets_found += result["secrets_found"]
                self.sast_issues_found += result["sast_issues"]
                self.deps_issues_found += result["deps_issues"]
                self.errors.extend(result["errors"])

            # Update final memory peak
            self.update_memory_peak()

            # Calculate duration
            duration = time.time() - self.start_time
            memory_used = self.memory_peak - self.memory_start

            # Generate summary report
            summary = {
                "test_type": "Linux Kernel Python Stress Test",
                "target_path": str(linux_path),
                "files_scanned": self.files_scanned,
                "secrets_found": self.secrets_found,
                "sast_issues_found": self.sast_issues_found,
                "deps_issues_found": self.deps_issues_found,
                "duration_seconds": round(duration, 2),
                "memory_peak_mb": round(self.memory_peak, 2),
                "memory_used_mb": round(memory_used, 2),
                "partitions_used": self.num_partitions,
                "errors_count": len(self.errors),
                "kafka_enabled": self.kafka_producer is not None,
                "status": "SUCCESS" if not self.errors else "PARTIAL_SUCCESS"
            }

            return summary

        except Exception as e:
            self.logger.error(f"Stress test failed: {e}")
            duration = time.time() - self.start_time
            self.update_memory_peak()
            memory_used = self.memory_peak - self.memory_start

            return {
                "test_type": "Linux Kernel Python Stress Test",
                "target_path": str(linux_path),
                "error": str(e),
                "duration_seconds": round(duration, 2),
                "memory_peak_mb": round(self.memory_peak, 2),
                "memory_used_mb": round(memory_used, 2),
                "status": "FAILED"
            }

    def print_summary_report(self, summary: Dict):
        """Print a comprehensive summary report."""
        print("\n" + "="*80)
        print("🎯 DECOYABLE LINUX KERNEL PYTHON STRESS TEST RESULTS")
        print("="*80)

        if summary.get("status") == "FAILED":
            print(f"❌ TEST FAILED: {summary.get('error', 'Unknown error')}")
            print(f"⏱️  Duration: {summary['duration_seconds']}s")
            print(f"🧠 Memory Peak: {summary['memory_peak_mb']} MB")
            return

        print(f"✅ Status: {summary['status']}")
        print(f"📁 Target: {summary['target_path']}")
        print(f"📊 Files Scanned: {summary['files_scanned']}")
        print(f"🔐 Secrets Found: {summary['secrets_found']}")
        print(f"🐛 SAST Issues Found: {summary['sast_issues_found']}")
        print(f"📦 Dependency Issues Found: {summary['deps_issues_found']}")
        print(f"⏱️  Duration: {summary['duration_seconds']}s")
        print(f"🧠 Memory Peak: {summary['memory_peak_mb']} MB")
        print(f"💾 Memory Used: {summary['memory_used_mb']} MB")
        print(f"🔀 Partitions: {summary['partitions_used']}")
        print(f"📡 Kafka Enabled: {summary['kafka_enabled']}")

        if summary['errors_count'] > 0:
            print(f"⚠️  Errors: {summary['errors_count']}")

        # Performance analysis
        if summary['files_scanned'] > 0:
            files_per_second = summary['files_scanned'] / summary['duration_seconds']
            print(f"⚡ Performance: {files_per_second:.1f} files/second")

        if summary['duration_seconds'] < 60:
            print("🚀 ACHIEVEMENT: Sub-minute completion! ⚡")
        else:
            print(f"📊 Completed in {summary['duration_seconds']/60:.1f} minutes")

        total_findings = (summary['secrets_found'] +
                         summary['sast_issues_found'] +
                         summary['deps_issues_found'])

        if total_findings > 0:
            print(f"🎯 Total Security Findings: {total_findings}")
            print("🔍 DECOYABLE successfully detected real security issues!")

        print("="*80)


async def main():
    """Main entry point for the stress test."""
    import argparse

    parser = argparse.ArgumentParser(description="DECOYABLE Linux Kernel Python Stress Test")
    parser.add_argument("--linux-path", type=str, default="./linux",
                       help="Path to Linux kernel directory (default: ./linux)")
    parser.add_argument("--partitions", type=int, default=5,
                       help="Number of concurrent partitions (default: 5)")
    parser.add_argument("--config", type=str,
                       help="Path to config file")

    args = parser.parse_args()

    # Setup services (following main.py pattern)
    config = Settings()
    registry = ServiceRegistry()
    logging_service = setup_logging_service(config)

    # Register core services
    registry.register_instance("config", config)
    registry.register_instance("logging", logging_service)
    registry.register_instance("registry", registry)

    # Initialize cache service
    try:
        from decoyable.core.cache_service import CacheService
        cache_service = CacheService(registry)
        registry.register_instance("cache_service", cache_service)
    except Exception as exc:
        logging_service.get_logger("stress_test").warning(f"Cache service not available: {exc}")
        cache_service = None

    # Initialize scanner service
    try:
        scanner_service = ScannerService(config, logging_service, cache_service)
        registry.register_instance("scanner_service", scanner_service)
    except Exception as exc:
        logging_service.get_logger("stress_test").error(f"Scanner service not available: {exc}")
        return 1

    # Create stress test
    stress_test = LinuxKernelStressTest(config, registry, logging_service)
    stress_test.num_partitions = args.partitions

    # Run the stress test
    linux_path = Path(args.linux_path)
    summary = await stress_test.run_stress_test(linux_path)

    # Print results
    stress_test.print_summary_report(summary)

    # Exit with appropriate code
    if summary.get("status") == "FAILED":
        return 1
    elif summary.get("errors_count", 0) > 0:
        return 2  # Partial success with errors
    else:
        return 0  # Complete success


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)