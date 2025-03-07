"""
Rate Limiter Module

This module handles rate limiting for TCP port scanning.

Functions:
    calculate_concurrency_limit: Calculate concurrency limit based on target count
    RateLimiter: Class for rate limiting
"""

import logging
import time
from typing import Dict, List, Any, Optional, Callable
import threading

logger = logging.getLogger(__name__)


def calculate_concurrency_limit(target_count: int) -> int:
    """
    Calculate concurrency limit based on target count.
    
    Concurrency limits:
    - General limit: ≤ 1,000 concurrent jobs
    - 4,096 hosts: ≤ 400-500 concurrent scans
    - 1,024 hosts: ≤ 100-200 concurrent scans
    - 256 hosts: ≤ 50 concurrent scans
    
    Args:
        target_count (int): Number of targets
        
    Returns:
        int: Concurrency limit
    """
    # Calculate concurrency limit based on target count
    if target_count >= 4096:
        return 450  # Middle of 400-500 range
    elif target_count >= 1024:
        return 150  # Middle of 100-200 range
    elif target_count >= 256:
        return 50
    else:
        # For smaller target counts, use a proportional limit
        # but ensure it's at least 10 and at most 50
        return max(10, min(50, target_count // 5))


class RateLimiter:
    """
    Rate limiter for controlling scan concurrency and timing.
    """
    
    def __init__(self, max_concurrency: int, min_delay_ms: int = 49, max_delay_ms: int = 199):
        """
        Initialize rate limiter.
        
        Args:
            max_concurrency (int): Maximum number of concurrent operations
            min_delay_ms (int): Minimum delay between operations in milliseconds
            max_delay_ms (int): Maximum delay between operations in milliseconds
        """
        self.max_concurrency = max_concurrency
        self.min_delay_ms = min_delay_ms
        self.max_delay_ms = max_delay_ms
        self.semaphore = threading.Semaphore(max_concurrency)
        self.last_operation_time = 0
        self.lock = threading.Lock()
    
    def acquire(self) -> None:
        """
        Acquire permission to perform an operation.
        This will block if the concurrency limit has been reached.
        """
        self.semaphore.acquire()
    
    def release(self) -> None:
        """
        Release permission after an operation is complete.
        """
        self.semaphore.release()
    
    def wait_for_next_operation(self) -> None:
        """
        Wait for the appropriate time before the next operation.
        This implements a variable delay between operations.
        """
        with self.lock:
            # Calculate delay
            from ..utils import generate_random_delay
            delay = generate_random_delay(self.min_delay_ms, self.max_delay_ms)
            
            # Calculate next operation time
            current_time = time.time()
            next_operation_time = max(current_time, self.last_operation_time + delay)
            
            # Wait until next operation time
            wait_time = next_operation_time - current_time
            if wait_time > 0:
                time.sleep(wait_time)
            
            # Update last operation time
            self.last_operation_time = time.time()
    
    def __enter__(self):
        """
        Context manager entry.
        """
        self.acquire()
        self.wait_for_next_operation()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit.
        """
        self.release()


def execute_with_rate_limit(
    func: Callable,
    items: List[Any],
    max_concurrency: int,
    min_delay_ms: int = 49,
    max_delay_ms: int = 199,
    callback: Optional[Callable] = None
) -> List[Any]:
    """
    Execute a function on a list of items with rate limiting.
    
    Args:
        func (Callable): Function to execute
        items (List[Any]): List of items to process
        max_concurrency (int): Maximum number of concurrent operations
        min_delay_ms (int): Minimum delay between operations in milliseconds
        max_delay_ms (int): Maximum delay between operations in milliseconds
        callback (Optional[Callable]): Callback function to call after each item is processed
        
    Returns:
        List[Any]: List of results
    """
    # Create rate limiter
    rate_limiter = RateLimiter(max_concurrency, min_delay_ms, max_delay_ms)
    
    # Create results list
    results = []
    
    # Create lock for results list
    results_lock = threading.Lock()
    
    # Create progress counter
    progress_counter = [0]
    progress_lock = threading.Lock()
    
    def worker(item, index):
        # Acquire rate limiter
        with rate_limiter:
            # Execute function
            result = func(item)
            
            # Add result to results list
            with results_lock:
                results.append(result)
            
            # Update progress counter
            with progress_lock:
                progress_counter[0] += 1
                if callback:
                    callback(progress_counter[0], len(items))
    
    # Create threads
    threads = []
    for i, item in enumerate(items):
        thread = threading.Thread(target=worker, args=(item, i))
        threads.append(thread)
    
    # Start threads
    for thread in threads:
        thread.start()
    
    # Wait for threads to complete
    for thread in threads:
        thread.join()
    
    return results
