"""
Embedded Python Block: Dynamic Threshold Controller

This block monitors the autocorrelation ratio input and dynamically adjusts
the sync_short threshold to optimize frame detection based on signal conditions.

Ports:
  - Input (float): autocorrelation ratio (same signal fed to sync_short port 2)
  - Output (float): pass-through of input (for monitoring)
  - Message out: threshold updates (optional, for logging)

The block maintains statistics on the input signal and adjusts the threshold
to balance between detecting weak frames and avoiding false triggers.
"""

import numpy as np
from gnuradio import gr
import pmt
import time


class DynamicThreshold(gr.sync_block):
    """
    Dynamic threshold controller for IEEE 802.11 sync_short block.
    
    Monitors autocorrelation ratio and adjusts threshold based on:
    - Running statistics of the correlation peaks
    - Noise floor estimation
    - Detection rate feedback
    """

    def __init__(self, sync_short_block=None, 
                 min_threshold=0.4, max_threshold=0.95,
                 initial_threshold=0.8,
                 adaptation_rate=0.01,
                 window_size=10000,
                 update_interval=0.5,
                 target_peak_ratio=0.7,
                 enable_auto=True):
        """
        Args:
            sync_short_block: Reference to ieee802_11.sync_short block instance
            min_threshold: Minimum allowed threshold (lower = more sensitive)
            max_threshold: Maximum allowed threshold (higher = fewer false positives)
            initial_threshold: Starting threshold value
            adaptation_rate: How fast to adjust (0.001 = slow, 0.1 = fast)
            window_size: Number of samples for statistics window
            update_interval: Seconds between threshold updates
            target_peak_ratio: Target ratio of peaks above threshold (0.5-0.9)
            enable_auto: Enable automatic threshold adjustment
        """
        gr.sync_block.__init__(
            self,
            name="Dynamic Threshold",
            in_sig=[np.float32],  # autocorrelation ratio input
            out_sig=[np.float32]  # pass-through for monitoring
        )
        
        # Store reference to sync_short block
        self.sync_short_block = sync_short_block
        
        # Threshold bounds
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.current_threshold = initial_threshold
        
        # Adaptation parameters
        self.adaptation_rate = adaptation_rate
        self.window_size = window_size
        self.update_interval = update_interval
        self.target_peak_ratio = target_peak_ratio
        self.enable_auto = enable_auto
        
        # Statistics tracking
        self.sample_buffer = np.zeros(window_size, dtype=np.float32)
        self.buffer_idx = 0
        self.buffer_filled = False
        
        # Peak detection state
        self.peak_count = 0
        self.sample_count = 0
        
        # Timing
        self.last_update_time = time.time()
        
        # Message port for threshold updates (optional monitoring)
        self.message_port_register_out(pmt.intern("threshold"))
        
        # Apply initial threshold
        self._apply_threshold(self.current_threshold)
        
        print(f"[DynamicThreshold] Initialized: threshold={initial_threshold:.3f}, "
              f"range=[{min_threshold:.2f}, {max_threshold:.2f}], "
              f"auto={'ON' if enable_auto else 'OFF'}")

    def _apply_threshold(self, new_threshold):
        """Apply threshold to the sync_short block."""
        # Clamp to valid range
        new_threshold = max(self.min_threshold, min(self.max_threshold, new_threshold))
        self.current_threshold = new_threshold
        
        if self.sync_short_block is not None:
            try:
                self.sync_short_block.set_threshold(new_threshold)
            except Exception as e:
                print(f"[DynamicThreshold] Failed to set threshold: {e}")
        
        # Publish threshold update message
        msg = pmt.cons(
            pmt.intern("threshold"),
            pmt.from_double(new_threshold)
        )
        self.message_port_pub(pmt.intern("threshold"), msg)

    def set_sync_short_block(self, block):
        """Set or update the sync_short block reference at runtime."""
        self.sync_short_block = block
        self._apply_threshold(self.current_threshold)
        print(f"[DynamicThreshold] Attached to sync_short block")

    def set_enable_auto(self, enable):
        """Enable or disable automatic threshold adjustment."""
        self.enable_auto = enable
        print(f"[DynamicThreshold] Auto-adjustment: {'ON' if enable else 'OFF'}")

    def set_manual_threshold(self, threshold):
        """Manually set threshold (also updates current_threshold for auto mode)."""
        self._apply_threshold(threshold)
        print(f"[DynamicThreshold] Manual threshold set: {threshold:.3f}")

    def set_adaptation_rate(self, rate):
        """Set adaptation rate (0.001 = slow, 0.1 = fast)."""
        self.adaptation_rate = max(0.0001, min(0.5, rate))

    def set_target_peak_ratio(self, ratio):
        """Set target peak ratio (0.5-0.9)."""
        self.target_peak_ratio = max(0.3, min(0.95, ratio))

    def get_threshold(self):
        """Get current threshold value."""
        return self.current_threshold

    def get_stats(self):
        """Get current statistics dictionary."""
        if self.buffer_filled:
            data = self.sample_buffer
        else:
            data = self.sample_buffer[:self.buffer_idx] if self.buffer_idx > 0 else np.array([0.0])
        
        return {
            'threshold': self.current_threshold,
            'mean': float(np.mean(data)),
            'std': float(np.std(data)),
            'max': float(np.max(data)),
            'min': float(np.min(data)),
            'percentile_90': float(np.percentile(data, 90)) if len(data) > 0 else 0.0,
            'percentile_99': float(np.percentile(data, 99)) if len(data) > 0 else 0.0,
            'peak_ratio': self.peak_count / max(1, self.sample_count),
        }

    def _update_statistics(self, samples):
        """Update running statistics with new samples."""
        n_samples = len(samples)
        
        # Update circular buffer
        for i in range(n_samples):
            self.sample_buffer[self.buffer_idx] = samples[i]
            self.buffer_idx = (self.buffer_idx + 1) % self.window_size
            if self.buffer_idx == 0:
                self.buffer_filled = True
        
        # Count peaks above current threshold
        peaks = np.sum(samples > self.current_threshold)
        self.peak_count += peaks
        self.sample_count += n_samples

    def _compute_adaptive_threshold(self):
        """Compute new threshold based on signal statistics."""
        if not self.buffer_filled and self.buffer_idx < self.window_size // 10:
            # Not enough data yet
            return self.current_threshold
        
        # Get current data
        if self.buffer_filled:
            data = self.sample_buffer
        else:
            data = self.sample_buffer[:self.buffer_idx]
        
        # Compute statistics
        mean_val = np.mean(data)
        std_val = np.std(data)
        p90 = np.percentile(data, 90)
        p99 = np.percentile(data, 99)
        max_val = np.max(data)
        
        # Current peak ratio
        current_peak_ratio = self.peak_count / max(1, self.sample_count)
        
        # Adaptive threshold strategies:
        # 1. If too few peaks detected (ratio < target), lower threshold
        # 2. If too many peaks (possible false triggers), raise threshold
        # 3. Use signal statistics to find optimal operating point
        
        # Strategy: Threshold should be between noise floor and signal peaks
        # Noise floor estimate: mean + 2*std (captures ~95% of noise)
        # Signal peak estimate: 90th-99th percentile
        
        noise_floor = mean_val + 2 * std_val
        signal_estimate = (p90 + p99) / 2
        
        # Target threshold: between noise floor and signal
        # Weight towards signal estimate for reliable detection
        target_threshold = noise_floor * 0.3 + signal_estimate * 0.7
        
        # Adjust based on peak ratio feedback
        ratio_error = current_peak_ratio - self.target_peak_ratio
        
        if abs(ratio_error) > 0.1:
            # Significant deviation from target
            if ratio_error > 0:
                # Too many peaks -> raise threshold
                adjustment = self.adaptation_rate * (1 + ratio_error)
            else:
                # Too few peaks -> lower threshold  
                adjustment = -self.adaptation_rate * (1 - ratio_error)
            
            target_threshold = self.current_threshold + adjustment
        
        # Smooth transition
        new_threshold = (1 - self.adaptation_rate) * self.current_threshold + \
                        self.adaptation_rate * target_threshold
        
        # Clamp to valid range
        new_threshold = max(self.min_threshold, min(self.max_threshold, new_threshold))
        
        return new_threshold

    def work(self, input_items, output_items):
        """Process samples and update threshold."""
        in0 = input_items[0]
        out0 = output_items[0]
        n_samples = len(in0)
        
        # Pass through input to output
        out0[:n_samples] = in0[:n_samples]
        
        # Update statistics
        self._update_statistics(in0[:n_samples])
        
        # Check if it's time to update threshold
        current_time = time.time()
        if self.enable_auto and (current_time - self.last_update_time) >= self.update_interval:
            new_threshold = self._compute_adaptive_threshold()
            
            if abs(new_threshold - self.current_threshold) > 0.001:
                old_threshold = self.current_threshold
                self._apply_threshold(new_threshold)
                
                stats = self.get_stats()
                print(f"[DynamicThreshold] {old_threshold:.3f} -> {new_threshold:.3f} "
                      f"(mean={stats['mean']:.3f}, p90={stats['percentile_90']:.3f}, "
                      f"peaks={stats['peak_ratio']:.1%})")
            
            # Reset counters for next interval
            self.peak_count = 0
            self.sample_count = 0
            self.last_update_time = current_time
        
        return n_samples
