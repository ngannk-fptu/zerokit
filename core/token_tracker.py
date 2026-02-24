import os
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class BudgetExceededError(Exception):
    """Raised when LLM usage exceeds configured budget limits."""
    pass

class TokenTracker:
    """
    Tracks token usage and enforces cost limits to prevent runaway API expenses.
    """
    
    def __init__(self):
        self.max_tokens = int(os.getenv("MAX_TOKENS_PER_RUN", "100000"))
        self.max_dollars = float(os.getenv("MAX_DOLLAR_LIMIT", "10.0"))
        
        # Pricing per 1K tokens (update based on Gemini pricing)
        self.input_price_per_1k = float(os.getenv("GEMINI_INPUT_PRICE_PER_1K", "0.00025"))
        self.output_price_per_1k = float(os.getenv("GEMINI_OUTPUT_PRICE_PER_1K", "0.0005"))
        
        # Running totals
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        
        logger.info(f"TokenTracker initialized: Max {self.max_tokens} tokens, ${self.max_dollars} limit")
    
    def add_usage(self, input_tokens: int, output_tokens: int):
        """
        Record token usage and update cost.
        
        Args:
            input_tokens: Number of prompt tokens
            output_tokens: Number of completion tokens
        
        Raises:
            BudgetExceededError: If limits are exceeded
        """
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        
        # Calculate incremental cost
        input_cost = (input_tokens / 1000) * self.input_price_per_1k
        output_cost = (output_tokens / 1000) * self.output_price_per_1k
        self.total_cost += (input_cost + output_cost)
        
        logger.debug(f"Token usage: +{input_tokens} in, +{output_tokens} out (${input_cost + output_cost:.4f})")
        
        # Check limits after adding
        self.check_limits()
    
    def check_limits(self):
        """
        Verify current usage is within limits.
        
        Raises:
            BudgetExceededError: If token or dollar limit exceeded
        """
        total_tokens = self.total_input_tokens + self.total_output_tokens
        
        if total_tokens > self.max_tokens:
            msg = (f"Token limit exceeded: {total_tokens}/{self.max_tokens} tokens used. "
                   f"Increase MAX_TOKENS_PER_RUN or reduce scan scope.")
            logger.error(msg)
            raise BudgetExceededError(msg)
        
        if self.total_cost > self.max_dollars:
            msg = (f"Cost limit exceeded: ${self.total_cost:.2f}/${self.max_dollars:.2f} spent. "
                   f"Increase MAX_DOLLAR_LIMIT or enable more aggressive caching.")
            logger.error(msg)
            raise BudgetExceededError(msg)
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for a given token count without recording it."""
        input_cost = (input_tokens / 1000) * self.input_price_per_1k
        output_cost = (output_tokens / 1000) * self.output_price_per_1k
        return input_cost + output_cost
    
    def get_current_usage(self) -> Dict:
        """Get current usage statistics."""
        total_tokens = self.total_input_tokens + self.total_output_tokens
        
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": total_tokens,
            "total_cost_usd": round(self.total_cost, 4),
            "max_tokens": self.max_tokens,
            "max_dollars": self.max_dollars,
            "tokens_remaining": self.max_tokens - total_tokens,
            "dollars_remaining": round(self.max_dollars - self.total_cost, 4),
            "usage_percent": round((total_tokens / self.max_tokens) * 100, 2),
            "budget_percent": round((self.total_cost / self.max_dollars) * 100, 2)
        }
    
    def reset(self):
        """Reset tracker (typically at start of new pipeline run)."""
        logger.info(f"Resetting tracker. Previous usage: {self.get_current_usage()}")
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
    
    def __repr__(self):
        stats = self.get_current_usage()
        return (f"<TokenTracker: {stats['total_tokens']}/{stats['max_tokens']} tokens, "
                f"${stats['total_cost_usd']}/${stats['max_dollars']}>")
